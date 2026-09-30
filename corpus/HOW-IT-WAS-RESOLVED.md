# How each lab was resolved

The resolution layer: for every engagement, **the class, the discriminator that
settled it, and where the evidence is**. Derived from the writeups, not from
anyone's memory — which is why the columns can be checked.

**Read this first if you read nothing else.** Forty-five of the fifty-two engagements carry
no reward value, and that is a *measurement*, not an oversight — the criterion is stated
below, because an unstated criterion is how a count rots. Four produced a
class the queue had mislabelled. Six carry a defect in the lab's own design. One
cannot be obtained at all. A report that says "52 of 52 solved" is wrong in five
different ways, and this file is where those five are named.

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
| [163](163/OFUSKEIT-WRITEUP.md) Ofuskeit | JS deobfuscation | the client string table is attack surface | `FLAG{}` recovered |
| [167](167/WINFAKE-WRITEUP.md) WinFake | el código fuente **es** la entrada | CSS inválido (`top: pipe;`, `index.html:14`) **nombra la cuenta**, y el caso especial `su root` (`windows.py:215`) está **ausente** de la blocklist de 18 de la línea 35 | parcial: `user.txt` leído en el target como `uid=1000`; `root.txt` sólo como propiedad de la imagen |
| [168](168/PINGCTF-WRITEUP.md) PingCTF | ejecución de comandos; el filtro es **ninguno** | la app se distribuye **sin su dependencia** (`ping_rc=127`): el `200` de 359 B es el fallo del sumidero y `&&` **nunca dispara** — y la ausencia de filtro la establecen **recuentos con control positivo**, no un 403 | ausente, probado: `FLAG{` en 0 de 15 132 ficheros |
| [172](172/CROSSFI-WRITEUP.md) Crossfi | CSRF, two levels | the token lives in the cookie ⇒ forgeable | `FLAG{}` recovered |
| [186](186/TOKENASO-WRITEUP.md) Tokenaso | race condition | the check and the act, measured apart | absent, proven |
| [188](188/WARGAMES-WRITEUP.md) Wargames | reconocimiento; la credencial vive en la **capa de build** | la credencial existe **sólo en una capa de build**: el `chpasswd` de `docker history` la deja en claro y **ningún fichero de ejecución** la contiene — `/etc/shadow` guarda un hash yescrypt, no hay `.bash_history`, ni `authorized_keys`, ni script de build | `WOPR{…}` recuperado a `euid=0`; no hay `FLAG{}` |
| [189](189/ROLAROLA-WRITEUP.md) Rolarola | command injection + pickle | an **undeclared** sudoers grant, no arg restriction | absent, proven |
| [209](209/PROFETAS-WRITEUP.md) Profetas | XXE + deobfuscation | a return value known in advance | `FLAG{}` recovered |
| [218](218/INTERNAL-WRITEUP.md) Internal | two-layer PHP WAF | two 403 bodies, one WAF — hash them separately | `FLAG{}` recovered |
| [220](220/CUENTAATRAS-WRITEUP.md) CuentaAtrás | account lifecycle | a confirmation channel that **does not exist** | absent; reward unreachable |
| [238](238/AUTOESCUELA-WRITEUP.md) Autoescuela | WebSocket → RCE | the advisory, read from four sources | absent, proven |
| [243](243/DUQUE-WRITEUP.md) Duque | dos bugs web, y son **independientes** | el admin entra **sin inyección alguna** (`Admin`/`admin123`, 200/79 B) ⇒ arreglar la SQLi no arregla el otro; y el caso intermedio es un **refusal** (5 467 B, `Acceso Denegado`), no una lectura cruzada | ausente, probado, con control positivo |
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
| [6→268](INDEX.md) kmspwned | — | **unobtainable**: truncated at 75–95%, no Range | never reached |

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
4. **One is permanently unobtainable.** 268 is truncated by the server and there is
   no Range, so it cannot be resumed. Not pending work.
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
