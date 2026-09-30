# How each lab was resolved

The resolution layer: for every engagement, **the class, the discriminator that
settled it, and where the evidence is**. Derived from the writeups, not from
anyone's memory — which is why the columns can be checked.

**Read this first if you read nothing else.** Nine of the forty-five engagements do
not have a reward, and that is a *measurement*, not an oversight. Four produced a
class the queue had mislabelled. Three carry a defect in the lab's own design. One
cannot be obtained at all. A report that says "45 of 45 solved" is wrong in five
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
| [172](172/CROSSFI-WRITEUP.md) Crossfi | CSRF, two levels | the token lives in the cookie ⇒ forgeable | `FLAG{}` recovered |
| [186](186/TOKENASO-WRITEUP.md) Tokenaso | race condition | the check and the act, measured apart | absent, proven |
| [189](189/ROLAROLA-WRITEUP.md) Rolarola | command injection + pickle | an **undeclared** sudoers grant, no arg restriction | absent, proven |
| [209](209/PROFETAS-WRITEUP.md) Profetas | XXE + deobfuscation | a return value known in advance | `FLAG{}` recovered |
| [218](218/INTERNAL-WRITEUP.md) Internal | two-layer PHP WAF | two 403 bodies, one WAF — hash them separately | `FLAG{}` recovered |
| [220](220/CUENTAATRAS-WRITEUP.md) CuentaAtrás | account lifecycle | a confirmation channel that **does not exist** | absent; reward unreachable |
| [238](238/AUTOESCUELA-WRITEUP.md) Autoescuela | WebSocket → RCE | the advisory, read from four sources | absent, proven |
| [249](249/ADOPTING-WRITEUP.md) Adopting | cache deception | the cache is **in-process**, key has no `Host` | functional; no `FLAG{}` |
| [255](255/PINGUPENGUIN-WRITEUP.md) PinguPenguin | Spring Boot actuator | the version read from the artefact | `FLAG{}` recovered |
| [264](264/APKADMIN-WRITEUP.md) ApkAdmin | mobile / APK | `targetSdk≥31` makes `exported` a **decision** | absent, searched at root |
| [271](271/BALUHOME-WRITEUP.md) BaluHome | stored XSS → no `httpOnly` → RCE | the cookie flag, measured both ways | `FLAG{}` recovered |
| [281](281/PIPEPWNED-WRITEUP.md) PipePwned | CI runner abuse | runner identity vs writer identity | `FLAG{}` recovered |
| [283](283/LOS-3-HACKERS-WRITEUP.md) Los 3 Hackers | **previene vs detecta** | the same filter, measured in both directions | `FLAG{}` recovered |
| [292](292/ACME-WRITEUP.md) Acme | pre-auth credential channel | world-writable docroot, execution identity read | `FLAG{}` recovered |
| [293](293/ZABBIXPLOIT-WRITEUP.md) Zabbixploit | SQLi → session hijack | the token at a **fixed offset**, same in both cases | `FLAG{}` recovered |
| [295](295/BAREMETAL-WRITEUP.md) Baremetal | IPMI → hash → GRUB | bare metal and BMC, absent from a container world | `FLAG{}` recovered |
| [296](296/ASTURIAS-WRITEUP.md) Asturias | unprotected endpoints | derive the sink, never look for the label | `FLAG{}` recovered |
| [6→268](INDEX.md) kmspwned | — | **unobtainable**: truncated at 75–95%, no Range | never reached |

---

## The five ways "45 of 45 solved" is wrong

1. **Nine have no reward, proven.** 34 of 45 carry a literal `FLAG{}`. The other
   eleven are absences with a search and a count behind them, which is a different
   claim from "solved" and is recorded as such.
2. **Four were mislabelled by the queue.** Labs 32 and 220 are not WordPress; 12
   ships a different plugin than the catalog names; 26 is not the class advertised.
   A class label is a filename, not a fingerprint.
3. **Three carry a defect in the lab's own design** — 112's chain cannot run on its
   image, 102's entry path is unresolved, 220's reward is unreachable from the
   identity reached. Reported as the lab's problem, not the tester's.
4. **One is permanently unobtainable.** 268 is truncated by the server and there is
   no Range, so it cannot be resumed. Not pending work.
5. **One did not fully succeed and says so.** Lab 102 reads its password with root
   on the artefact, so the external entry is unresolved. Lab 115 reached no RCE and
   lists its escalation as an inference under NOT tested.

---

## What was wrong and got fixed

The corpus is not self-certifying. A four-way adversarial audit over all 45 found
**five CRITICAL defects**, all re-verified and all corrected:

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
