# How each lab was resolved

The resolution layer: for every engagement, **the class, the discriminator that
settled it, and where the evidence is**. Derived from the writeups, not from
anyone's memory — which is why the columns can be checked.

**Read this first if you read nothing else.** Forty-one of the sixty-two engagements carry
no reward value — **thirty-eight** measured as none at all, plus **three** whose token exists
but was never reached — and that is a *measurement*, not an oversight: the criterion is
[`INDEX.md`](INDEX.md)'s own, restated at the foot of that table, because an unstated
criterion is how a count rots. Four produced a class the queue had mislabelled. Six carry a
defect in the lab's own design. **Two** cannot be obtained at all. A report that says
"52 of 52 solved" is wrong in five different ways, and this file is where those five are named.

---

## The shape of a resolution

Every chain in this corpus ends the same way, and that is the transferable part:

```
get the archive          verify before deploying, not after
read the source          the sink, the version, and the middleware order are all here
identify the class       from the entry criterion, not from the lab's name
prove the positive       a control that has never fired is not a control
chained identity         uid/euid at every hop, never "root"
prove the negative       with a work count, or it is untested
restore and re-verify    from the image, checked positively
feed forward             extend the class table, or say the class already exists
```

Two of those steps are where the corpus went wrong, repeatedly, and they are the
reason this file exists: **the positive control** and **the negative's work count**.

---

## Resolution map

`Discriminator` is the one measurement that settled the class. `Reward` is what the
platform actually served, not what the writeup hoped for.

**The `Class` column below spans three platforms, and its entries are not comparable
until you know which one a row came from.** 32 is Joomla 4.0.3 and 82 is Drupal 8.5.0;
neither is WordPress, and the *unit of trust* differs in all three, so a rule that holds
for one does not transfer to the next without being re-derived:

| Platform | Row | What the unit of trust is | So a write primitive is… |
|---|---|---|---|
| WordPress | 61 | **an activation list** — `wp_options.active_plugins` names files core `include`s; no manifest, no per-item permission, no sandbox | code execution, with no further step |
| Drupal | 82 | **the compiled service container**, cached in a **database row** (`cache_container`: 2 rows, 643 537 B; state in `config.core.extension`, 42 names) | a `services.yml` or a config object. And measured: the `services.yml` **does not exist**, so the guard is a directory mode — `sites/default` is `555` — which one `chmod` reopens with nothing in the application objecting |
| Joomla | 32 | **neither** — no `wp-content`, no `wp-includes`, no plugin: the tree is core | 8 118 writable files, **0** of them owned by another principal; 16 stock setuid; `getcap` empty |

The practical consequence: *"activation is not a boundary"* is a WordPress sentence. In
Drupal there is no activation to abuse and the file that would be its analogue is absent;
in Joomla the extension tree is not a trust surface at all, so the same write lands
nowhere. **A class claim here holds for the platform it was measured on, and the row
names which.**

| Lab | Class | Discriminator | Reward |
|---|---|---|---|
| [6](6/GRANDMA-WRITEUP.md) Grandma | LFI → log poisoning → tunnelling | aiohttp advisory, quoted from upstream; CVSS recomputes to 5.9 | absent, proven |
| [12](12/COLLECTIONS-WRITEUP.md) Collections | content-type: declared vs registered | the app's extension test and the server's filename test **accept different name sets** | absent; MongoDB leg unreachable (no AVX) |
| [23](23/REVERSE-WRITEUP.md) reverse | log poisoning via LFI | the sink, read in the artefact | absent, proven |
| [26](26/404-NOT-FOUND-WRITEUP.md) 404-not-found | mislabelled LDAP injection | the process cannot speak LDAP at all | absent, proven |
| [32](32/VULNERAME-WRITEUP.md) Vulnerame | **Joomla 4.0.3, not WordPress** | `Version.php` reads 4/0/3; docroot merely *named* `wordpress` | absent, proven |
| [33](33/CHMOD-4755-WRITEUP.md) chmod-4755 | rbash escape + SUID | planted positive control re-run over 15 roots | absent, proven |
| [36](36/VERDEJO-WRITEUP.md) Verdejo | hash cracking | the shipped wordlists, run to a stated rate | absent, proven |
| [61](61/BADPLUGIN-WRITEUP.md) BadPlugin | plugin trust: activated code | 46 REST routes, all `manage_options`, **zero** `__return_true` | absent, proven |
| [62](62/RAAS-WRITEUP.md) Raas | reversing a ransomware binary | round-trip oracle on its own `system()` | functional reward, no `FLAG{}` |
| [65](65/SEEKER-WRITEUP.md) Seeker | subdomain fuzzing over virtual hosting | a name that **cannot exist** shares the baseline hash | absent, proven |
| [73](73/CHOCOPING-WRITEUP.md) ChocoPing | a deny-list gate whose **escape hatch is the bypass detector** → unescaped `shell_exec` → sudoers → ZipCrypto → pcap | `is_bypass_command` is `preg_match('/[a-zA-Z]+\\')` — **any `x\` opens it** — and `ping.php:22` is a bare `shell_exec($ip)` where `:17` escapes; `error.log` names `:17`'s own argument, so the empty first `<pre>` is the decoy, not a refusal | el par de credenciales del `.pcap`; **ambos fallan contra `su`**, así que no es un login — sin token de flag, `balutin` `uid=1000`, root no alcanzado |
| [77](77/GALERIA-WRITEUP.md) galeria | upload sin comprobación en la aplicación; los tres chequeos se reparten | `.php5` es el **único** nombre que voltea en el diferencial de cuatro estados de `.htaccess`: `AllowOverride All` vuelve decisiva la línea 2, que el mapa global `\.php(\..+)?$` rechaza; `dpkg -V libapache2-mod-php8.3` → `??5??????` sobre `php8.3.conf:29-31` | absent, proven — root alcanzado y `FLAG{` ausente en 14 193 ficheros a `euid=0` y en 35 270 796 724 B fuera |
| [78](78/BYPASSME-WRITEUP.md) Bypassme | bypass de autenticación por **subcadena**, sin SQL en la aplicación | `'1'='1zzz` sigue autenticando (`Location: index.php?page=welcome`) — ningún motor SQL aceptaría basura final; y `php -m` lista `PDO` **sin driver**, `/var/www` → **0** ficheros que mencionen `mysqli`, `pgsql` o `sqlite` | absent, proven: 9 prefijos, ambos casos y ambas llaves, **0** de 13 782 ficheros / 812 440 752 B, control verde primero |
| [82](82/EJOTAPETE-WRITEUP.md) Ejotapete | **Drupal 8.5.0**, no WordPress | el fix son 99 líneas **una capa por encima** de todo formulario: `diff -u` de `FormBuilder.php` 8.5.0→8.5.1 **no produce salida**, y `find -name RequestSanitizer.php` → **0** | secreto funcional, no `FLAG{}` (0 de 23 898 ficheros; el único `flag{` es una clase jQuery UI) |
| [83](83/GROOTI-WRITEUP.md) Grooti | enumeración; escalada = un bit de modo | `root:grooti` modo **764**: el grupo tiene `w` y `grooti` es su grupo primario — y el crontab de `grooti` **no puede dispararse nunca**, `/opt/cleanup.sh` es 754 y da **rc=126** leído como `grooti` | arte braille en `/root/grooti.txt` a `euid=0`; no `FLAG{}` |
| [84](84/WAFFY-WRITEUP.md) Waffy | ModSecurity + OWASP CRS | the CRS scores **variables**; the sink composes them | absent, proven |
| [85](85/AIDOR-WRITEUP.md) Aidor | IDOR ≠ unauthenticated | three byte-distinguishable cases in one handler | absent, proven |
| [87](87/WALKINGCMS-WRITEUP.md) WalkingCMS | enumeration, done properly | `COUNT(*)=1` makes 199 negatives evidence | absent, searched as euid=0 |
| [90](90/NORC-WRITEUP.md) Norc | real CVE in a WordPress plugin | advisory read from primary sources, not recalled | `FLAG{}` recovered |
| [93](93/PINGUINAZO-WRITEUP.md) Pinguinazo | a sudo grant naming an interpreter | `{{7*7}}` positive control **first** | `FLAG{}` recovered |
| [98](98/REDIRECTION-WRITEUP.md) Redirection | open redirect | **Apache builds the `Location` from the `Host`** | absent; no consumer exists |
| [102](102/ESCOLARES-WRITEUP.md) Escolares | WordPress + File Manager | phpass driven directly, oracle green | absent; entry path unresolved |
| [108](108/WHOIAM-WRITEUP.md) Whoiam | WordPress, salts | `pluggable.php` discards the install placeholder | absent, proven |
| [112](112/ASUCAR-WRITEUP.md) Asucar | **the lab's own chain does not run** | two required classes absent from the image | absent; root proved by other means |
| [113](113/ROAD-TO-OLYMPUS-WRITEUP.md) Road_To_Olympus | pivoting, three hosts | SOCKS scanned the *operator's* own machine | absent, proven |
| [115](115/MASTER-WRITEUP.md) Master | WordPress + LMS plugin | privilege reachability is **non-deterministic**: 41/57 then 1/57 | absent, proven |
| [117](117/PRESSENTER-WRITEUP.md) Pressenter | two vhosts, one a decoy | theme editor validated via loopback; plugin installer did not | absent, proven |
| [118](118/LOS-40-LADRONES-WRITEUP.md) los40ladrones | port knocking | a partial knock leaves **no** window | `FLAG{}` recovered |
| [129](129/DOCKHACKLAB-WRITEUP.md) DockHackLab | PHP upload + SSH key injection | the mode check, read **as the writing identity** | `FLAG{}` recovered |
| [141](141/DOCKERLABS-WRITEUP.md) DockerLabs | container security | socket exposed; a container **with** the socket as positive control | `FLAG{}` recovered |
| [146](146/ELEVATOR-WRITEUP.md) Elevator | global MIME→handler mapping | a 3-state `.htaccess` differential | `FLAG{}` recovered |
| [148](148/SPAIN-WRITEUP.md) Spain | buffer overflow + pickle | the KDF's **absence** in the import table | `FLAG{}` recovered |
| [162](162/PKGPOISON-WRITEUP.md) PkgPoison | `sudoers` **argument specification** delegating a package installer | `install *`: 14 forms measured, and `sudo -n /usr/bin/pip3 install ;id` reaches pip **literalmente** (`rc=2`, 6 274 B) — el `setup.py` elegido corre como `uid=0` | absent, proven a `uid=0`: 17 577 ficheros / 500 149 523 B / 6 patrones / 0 |
| [163](163/OFUSKEIT-WRITEUP.md) Ofuskeit | JS deobfuscation | the client string table is attack surface | `FLAG{}` recovered |
| [166](166/INFLUENCERHATE-WRITEUP.md) InfluencerHate | dos rutas de fuerza bruta sobre **dos almacenes de identidad** | **el almacén, no la tasa**: ruta A corre apr1 a 3 577/s contra 3 263 628/s de 1×MD5 = **912×**, y la ruta B evalúa **cero** candidatos por barrido; una escalera in-band da la respuesta **equivocada** (A es 1.71× más rápida) | absent, proven a `euid=0`: 6 patrones / 12 275 ficheros / 0, con 3 controles verdes |
| [167](167/WINFAKE-WRITEUP.md) WinFake | el código fuente **es** la entrada | CSS inválido (`top: pipe;`, `index.html:14`) **nombra la cuenta**, y el caso especial `su root` (`windows.py:215`) está **ausente** de la blocklist de 18 de la línea 35 | parcial: `user.txt` leído en el target como `uid=1000`; `root.txt` sólo como propiedad de la imagen |
| [168](168/PINGCTF-WRITEUP.md) PingCTF | ejecución de comandos; el filtro es **ninguno** | la app se distribuye **sin su dependencia** (`ping_rc=127`): el `200` de 359 B es el fallo del sumidero y `&&` **nunca dispara** — y la ausencia de filtro la establecen **recuentos con control positivo**, no un 403 | ausente, probado: `FLAG{` en 0 de 15 132 ficheros |
| [169](169/SPIDERROOT-WRITEUP.md) SpiderRoot | **la rama de detección del filtro es la divulgación** → SSH → panel de loopback → directorio escribible por grupo | la blacklist de 5 ítems de `multiverse.php:15` (`[ ' " UNION -- #`) **no interseca** con la regex de ofuscación `:46`, que casa `or` y `and` con cada letra en mayúscula o minúscula: el token literal `or` la atraviesa y dispara la rama que vuelca `$users` | `Grooti16` — `/root/flag.txt` leído a `euid=0` (insignia en braille + la firma); **no hay token `FLAG{}`**, y no se barrió el árbol en busca de él |
| [172](172/CROSSFI-WRITEUP.md) Crossfi | CSRF, two levels | the token lives in the cookie ⇒ forgeable | `FLAG{}` recovered |
| [186](186/TOKENASO-WRITEUP.md) Tokenaso | race condition | the check and the act, measured apart | absent, proven |
| [188](188/WARGAMES-WRITEUP.md) Wargames | reconocimiento; la credencial vive en la **capa de build** | la credencial existe **sólo en una capa de build**: el `chpasswd` de `docker history` la deja en claro y **ningún fichero de ejecución** la contiene — `/etc/shadow` guarda un hash yescrypt, no hay `.bash_history`, ni `authorized_keys`, ni script de build | `WOPR{…}` recuperado a `euid=0`; no hay `FLAG{}` |
| [189](189/ROLAROLA-WRITEUP.md) Rolarola | command injection + pickle | an **undeclared** sudoers grant, no arg restriction | absent, proven |
| [209](209/PROFETAS-WRITEUP.md) Profetas | XXE + deobfuscation | a return value known in advance | `FLAG{}` recovered |
| [218](218/INTERNAL-WRITEUP.md) Internal | two-layer PHP WAF | two 403 bodies, one WAF — hash them separately | `FLAG{}` recovered |
| [219](219/TALENT-WRITEUP.md) Talent | **la vulnerabilidad decisiva está en el artefacto de build, no en la web** | `/entrypoint.sh:115-116` corre `wp core install --admin_user="admin" --admin_password="admin"` — ningún CVE de WordPress la alcanza; y la escalada que sí anuncia está **rota**: `sudoers` nombra `/usr/bin/python3`, que **no existe en la imagen** (`sudo -l` verde, `command not found` al ejecutarlo) | `LNDSG98DSFG7D8SGY8SDFG9` — `/home/flag.txt` es `644 www-data:www-data`, así que la recompensa cae en el **primer** salto; root **no** obtenido |
| [220](220/CUENTAATRAS-WRITEUP.md) CuentaAtrás | account lifecycle | a confirmation channel that **does not exist** | absent; reward unreachable |
| [234](234/SECORNOTSEC-WRITEUP.md) SECorNOTsec | blocklist de cadenas; el bypass es un token que **nunca se listó** | `app.py:47` omite `&`, `<`, `>` y el salto de línea — y `app.py:58` lo dice: *"Vulnerable a inyección via '&' o '%0a'"* — mientras **13 de 13** tokens listados se bloquean a 2 239 B / 0.00 s con control positivo verde; los cuatro estados se separan por **bytes** (2 239 / 2 532 / 2 598 / 2 227), nunca por el código de estado | absent, proven a `euid=0`: 14 291 ficheros / 485 926 780 B, 4 controles positivos |
| [238](238/AUTOESCUELA-WRITEUP.md) Autoescuela | WebSocket → RCE | the advisory, read from four sources | absent, proven |
| [242](242/WORKCONNECT-WRITEUP.md) WorkConnect | oráculo de existencia sobre un identificador estructurado; **la etiqueta de la cola es el hallazgo** | `grep -rIo -i "dns" /opt/workconnect` → **0** y 0 sockets UDP retiran la clase DNS; `main.py:69-73` nombra la real, y 26 000 candidatos dan dos conjuntos de tamaño **disjuntos** (2 268 presente / 1 332 ausente), **0** INDETERMINADOS | absent, proven a `euid=0`: `FLAG{` → 0 de 13 969 ficheros / 291 034 473 B |
| [243](243/DUQUE-WRITEUP.md) Duque | dos bugs web, y son **independientes** | el admin entra **sin inyección alguna** (`Admin`/`admin123`, 200/79 B) ⇒ arreglar la SQLi no arregla el otro; y el caso intermedio es un **refusal** (5 467 B, `Acceso Denegado`), no una lectura cruzada | ausente, probado, con control positivo |
| [245](245/TRAILPACK-WRITEUP.md) TrailPack | cuatro bugs declarados: una puerta, tres colgantes, uno inerte | `X-Forwarded-For` **es** la clave del cubo y **nunca se valida como IP**: un valor constante **reutilizado** sigue limitando (contador `2 → 1 → 0`, 9 265 B, cuenta atrás 59) mientras los valores rotados lo **congelan** en `2`; 1 846 peticiones / 6.257 s = 295.0 req/s frente a 55.57 h | `FLAG{cl13nt_s1d3_r0l3_1s_n0_s3cur1ty}` |
| [249](249/ADOPTING-WRITEUP.md) Adopting | cache deception | the cache is **in-process**, key has no `Host` | functional; no `FLAG{}` |
| [255](255/PINGUPENGUIN-WRITEUP.md) PinguPenguin | Spring Boot actuator | the version read from the artefact | `FLAG{}` recovered |
| [264](264/APKADMIN-WRITEUP.md) ApkAdmin | mobile / APK | `targetSdk≥31` makes `exported` a **decision** | absent, searched at root |
| [271](271/BALUHOME-WRITEUP.md) BaluHome | stored XSS → no `httpOnly` → RCE | the cookie flag, measured both ways | `FLAG{}` recovered |
| [281](281/PIPEPWNED-WRITEUP.md) PipePwned | CI runner abuse | runner identity vs writer identity | `FLAG{}` recovered |
| [282](282/HANNAH-COFFEE-WRITEUP.md) Hannah's Coffee | LFI → log poisoning → RCE; escalada que no cierra | el secreto al que apunta el grant sudo (`G'2'ZkcHsulI*vE+D,`) **no autentica ninguna cuenta**: 0 coincidencias en 383 786 240 bytes de 12 050 ficheros, con control positivo verde | 2 × `dl{…}`, sólo con una credencial del host de build — inalcanzable desde el contenedor |
| [283](283/LOS-3-HACKERS-WRITEUP.md) Los 3 Hackers | **previene vs detecta** | the same filter, measured in both directions | `FLAG{}` recovered |
| [292](292/ACME-WRITEUP.md) Acme | pre-auth credential channel | world-writable docroot, execution identity read | `FLAG{}` recovered |
| [293](293/ZABBIXPLOIT-WRITEUP.md) Zabbixploit | SQLi → session hijack | the token at a **fixed offset**, same in both cases | `FLAG{}` recovered |
| [295](295/BAREMETAL-WRITEUP.md) Baremetal | IPMI → hash → GRUB | bare metal and BMC, absent from a container world | `FLAG{}` recovered |
| [296](296/ASTURIAS-WRITEUP.md) Asturias | unprotected endpoints | derive the sink, never look for the label | `FLAG{}` recovered |
| [254](INDEX.md) Gotham | — | **unobtainable, y no existe writeup**: el servidor sirve **107 479 040 B = 102.5 MiB exactos**, un límite redondo de proxy, y reporta *esa* longitud como `Content-Length` completa; las propias entradas del archivo declaran 107 575 879, así que **faltan 96 839 B**. Seis descargas, tamaño y fallo idénticos (§32) | never reached |
| [268](INDEX.md) kmspwned | — | **unobtainable, y no existe writeup**: `kmspwned.zip` muere entre el 75% y el 95% de sus **116 916 224 B** en cuatro intentos seguidos con `curl` saliendo en **0**, y `Range` se responde `200` en vez de `206`: la cola es inalcanzable | never reached |

---

## The five ways "52 of 52 solved" is wrong

1. **Forty-five of the fifty-two have no reward value.** Measured on the reward column
   with one stated criterion: a cell counts as a reward only if it contains a **literal
   value** — `FLAG{…}` or another `prefix{…}` token with content. A cell reading
   *"no `FLAG{}`"* counts as **no** reward, because it is. **Three** engagements carry a
   literal `FLAG{…}` (292, 255, 218), three more carry another format (`WOPR{…}` 188,
   `DL{…}` 238, `dl{…}` 282 — the last two unreachable from inside the target), and the
   remaining forty-five are absences with a search and a count behind them. A reward in
   another format is a reward; a reward you could not reach is not a solution.

   > This number was **wrong by sixteen** on first pass, in the very document that warns
   > about this defect. The tally counted `FLAG{` as a substring, which also matches a
   > cell saying *no* `FLAG{}` — so every measured absence scored as a reward. §26 is not a
   > lesson about grep patterns in a lab; it is a lesson about a number in a summary.
2. **Four were mislabelled by the queue.** Labs 32 and 220 are not WordPress; 12
   ships a different plugin than the catalog names; 26 is not the class advertised.
   A class label is a filename, not a fingerprint — and since lab 82 the corpus is no
   longer one platform to mislabel. See the three-platform table above.
3. **Six carry a defect in the lab's own design** — 112's chain cannot run on its
   image, 102's entry path is unresolved, 220's reward is unreachable from the
   identity reached, 168 ships an application whose own binary is missing, 282's
   `sudoers` grant points at a decoy secret, and 83's advertised database leg cannot
   execute as written. Reported as the lab's problem, not the tester's.
4. **Two are permanently unobtainable, for two different reasons.** **268 kmspwned**
   (`kmspwned.zip`, 116 916 224 B) dies between 75% and 95% on four consecutive
   attempts with `curl` exiting **0**, and `Range` is answered `200` instead of
   `206` — the tail is unreachable, so the transfer cannot be resumed. **254 Gotham**
   is a separate failure and not a restatement of it: the platform serves
   **107 479 040 B, exactly 102.5 MiB**, a round proxy boundary, and reports *that
   truncated length* as the complete `Content-Length`; the archive's own last entry
   declares 107 575 879, so **96 839 B are missing** and the headers say nothing
   about it (§32). Six downloads produced the identical size and the identical
   failure. Neither is pending work, and the second one is the one that a
   `size == expected` check cannot see.
5. **Four did not fully succeed and say so.** Lab 115 reached no RCE and lists its
   escalation as an inference under NOT tested. Lab 167 proves its `uid=0` leg on a
   **clone of the same image** and does not count it as the target. Lab 282 completes
   root with a credential from the image build metadata and labels that hop
   `OPERATOR-SIDE`. Lab 102 reads its password with root on the artefact, so the
   external entry is unresolved.

---

## What was wrong and got fixed

The corpus is not self-certifying. A four-way adversarial audit found **five CRITICAL
defects**, all re-verified and all corrected. It ran over the 45 writeups that existed
at the time; **the seven rows added above were not in its scope**, and nothing here
should be read as clearing them. The five it did find:

- a writeup that **credited a sibling lab with a mechanism it does not contain**,
  and used it to suppress a candidate finding
- a controls table asserting a boundary the filter does not have, contradicting
  the same document two lines above
- a count of "six of eight execute" against a table showing **two of seven**
- a `substr` offset wrong in both directions, sold as an offline proof
- a citation pointing at a file's docblock instead of the code it claimed

A native review of this corpus returns `risk_level: low`, `selected_lenses: []`,
reason `non_executable_only`. It cannot see any of that. **The receipt attests that
the change is documentation, not that the documentation is correct** — which is
why an adversarial read is a required step here, not a courtesy.

Full detail: [`../method/self-corrections.md`](../method/self-corrections.md) —
23 instrument failures, and the pattern that reduces all of them to one thing.

---

## Next step

[`../RUNBOOK.md`](../RUNBOOK.md) for the procedure,
[`INDEX.md`](INDEX.md) for the class table, and each writeup above for the
evidence. If a claim here is load-bearing enough to dispute, **re-fetch the
archive**: this corpus holds no artefacts, so it is a transcript, not a
reproduction.
