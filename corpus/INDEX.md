# Corpus index — 32 engagements

| # | Lab | Difficulty | Writeup | Class | Reward |
|---|-----|-----------|---------|-------|--------|
| 249 | Adopting | Medio | [`corpus/249/ADOPTING-WRITEUP.md`](249/ADOPTING-WRITEUP.md) | **Web cache deception, first evidence in the corpus** · la clave de caché no varía por identidad · la ruta clásica `/x.pdf/foo.css` se **refuta** aquí: la fuga real es una ruta dinámica legítima con extensión cacheable · `Cache-Control: private, no-store` es una petición, no un control | credencial SSH funcional (sin `FLAG{}`) |
| 296 | Asturias | Medio | [`corpus/296/ASTURIAS-WRITEUP.md`](296/ASTURIAS-WRITEUP.md) | Upload sin restricción · MIME map · orden de registro de middleware | — |
| 292 | Acme | Muy fácil | [`corpus/292/ACME-WRITEUP.md`](292/ACME-WRITEUP.md) | Credenciales en canal pre-auth · docroot world-writable · identidad de ejecución | `FLAG{wp2shell_…}` |
| 281 | PipePwned | Medio | [`corpus/281/PIPEPWNED-WRITEUP.md`](281/PIPEPWNED-WRITEUP.md) | SSTI · abuso de runner CI/CD · identidad ejecutor vs escritor | hex |
| 293 | Zabbixploit | Medio | [`corpus/293/ZABBIXPLOIT-WRITEUP.md`](293/ZABBIXPLOIT-WRITEUP.md) | SQLi CVE-2016-10134 · session hijack · allowlist que funcionó | texto plano |
| 271 | BaluHome | Medio | [`corpus/271/BALUHOME-WRITEUP.md`](271/BALUHOME-WRITEUP.md) | XSS almacenado · cookie sin `httpOnly` · RCE | — |
| 295 | Baremetal | Medio | [`corpus/295/BAREMETAL-WRITEUP.md`](295/BAREMETAL-WRITEUP.md) | BMC/IPMI en UDP invisible a TCP · GRUB | `Congratulations!` |
| 62 | Raas | Difícil | [`corpus/62/RAAS-WRITEUP.md`](62/RAAS-WRITEUP.md) | Reversing de ransomware · **padding no prueba nada en CBC** · SMB | credencial SSH |
| 209 | Profetas | Medio | [`corpus/209/PROFETAS-WRITEUP.md`](209/PROFETAS-WRITEUP.md) | SQLi · XXE · deofuscación `.pyc` · sudoers | dos `DL{}` |
| 146 | Elevator | Difícil | [`corpus/146/ELEVATOR-WRITEUP.md`](146/ELEVATOR-WRITEUP.md) | MIME map · escalera sudoers de 6 peldaños · `gcc` como driver | — |
| 255 | PinguPenguin | Difícil | [`corpus/255/PINGUPENGUIN-WRITEUP.md`](255/PINGUPENGUIN-WRITEUP.md) | Superficies de diagnóstico · heap dump · secreto de sesión | `FLAG{actuator_…}` |
| 186 | Tokenaso | Difícil | [`corpus/186/TOKENASO-WRITEUP.md`](186/TOKENASO-WRITEUP.md) | Carrera: **la ventana es del código** · criptografía | — |
| 26 | 404-not-found | Medio | [`corpus/26/404-NOT-FOUND-WRITEUP.md`](26/404-NOT-FOUND-WRITEUP.md) | LDAP **refutado** · vhost catch-all | md5 |
| 148 | Spain | Difícil | [`corpus/148/SPAIN-WRITEUP.md`](148/SPAIN-WRITEUP.md) | Buffer overflow · gadget `pickle` · inyección de argumentos sudo | — |
| 113 | Road_To_Olympus | Difícil | [`corpus/113/ROAD-TO-OLYMPUS-WRITEUP.md`](113/ROAD-TO-OLYMPUS-WRITEUP.md) | Pivoting multi-host · **plano de control ≠ plano de datos** | — |
| 65 | Seeker | Medio | [`corpus/65/SEEKER-WRITEUP.md`](65/SEEKER-WRITEUP.md) | Vhosting en dos direcciones · control de estabilidad | — |
| 6 | Grandma | Difícil | [`corpus/6/GRANDMA-WRITEUP.md`](6/GRANDMA-WRITEUP.md) | LFI aiohttp · **leer ≠ obtener** · CVE leído de fuente | — |
| 23 | reverse | Medio | [`corpus/23/REVERSE-WRITEUP.md`](23/REVERSE-WRITEUP.md) | Log poisoning · **el campo es el hallazgo** | — |
| 33 | chmod-4755 | Medio | [`corpus/33/CHMOD-4755-WRITEUP.md`](33/CHMOD-4755-WRITEUP.md) | rbash en dos capas · **el euid sobrevive por binario** | md5 |
| 163 | Ofuskeit | Medio | [`corpus/163/OFUSKEIT-WRITEUP.md`](163/OFUSKEIT-WRITEUP.md) | Deofuscación JS · **refutó** "el cliente documenta la API" | `chocolate123` |
| 238 | Autoescuela | Fácil | [`corpus/238/AUTOESCUELA-WRITEUP.md`](238/AUTOESCUELA-WRITEUP.md) | WebSocket · **el lab atribuyó mal su propio CVE** | `DL{g2QrDUvg…}` |
| 141 | DockerLabs | Fácil | [`corpus/141/DOCKERLABS-WRITEUP.md`](141/DOCKERLABS-WRITEUP.md) | Frontera de contenedor · **no disparó ningún escape** | — |
| 118 | Los 40 Ladrones | Fácil | [`corpus/118/LOS-40-LADRONES-WRITEUP.md`](118/LOS-40-LADRONES-WRITEUP.md) | Port knocking · **credenciales: medición, no éxito** | — |
| 129 | DockHackLab | Medio | [`corpus/129/DOCKHACKLAB-WRITEUP.md`](129/DOCKHACKLAB-WRITEUP.md) | `authorized_keys` · **dos identidades medidas** | — |
| 90 | Norc | Difícil | [`corpus/90/NORC-WRITEUP.md`](90/NORC-WRITEUP.md) | CVE-2023-6063 · **discrepancia de CVSS Scope** · capabilities | — |
| 283 | Los 3 Hackers | Fácil | [`corpus/283/LOS-3-HACKERS-WRITEUP.md`](283/LOS-3-HACKERS-WRITEUP.md) | Evasión de filtro · **previene vs detecta** | — |
| 93 | Pinguinazo | Fácil | [`corpus/93/PINGUINAZO-WRITEUP.md`](93/PINGUINAZO-WRITEUP.md) | Grant que nombra un intérprete · Werkzeug debug | — |
| 36 | Verdejo | Fácil | [`corpus/36/VERDEJO-WRITEUP.md`](36/VERDEJO-WRITEUP.md) | Cracking offline · **la línea base es un control** | — |
| 85 | Aidor | Fácil | [`corpus/85/AIDOR-WRITEUP.md`](85/AIDOR-WRITEUP.md) | IDOR · **IDOR ≠ no autenticado** · `session` reescrito desde el request | — |
| 172 | Crossfi | Medio | [`corpus/172/CROSSFI-WRITEUP.md`](172/CROSSFI-WRITEUP.md) | CSRF a dos niveles · **el token vive en la cookie ⇒ es falsificable** · `flask-wtf` instalado y nunca importado · el check de `Referer` corre **después** de la escritura · `env` SUID root: `uid=1000 euid=0` | — |
| 264 | ApkAdmin | Fácil | [`corpus/264/APKADMIN-WRITEUP.md`](264/APKADMIN-WRITEUP.md) | **Primer APK del corpus** · Activity exportada sin permiso · **la puerta es un extra que suministra el llamante** (`getBooleanExtra("isAdmin")`) · control de tres vías del manifest · `uid=1000(pingu)` → `uid=0(root)` | — (criterio: `id` → `uid=0(root)`) |
| 108 | Whoiam | Fácil | [`corpus/108/WHOIAM-WRITEUP.md`](108/WHOIAM-WRITEUP.md) | **WordPress como plataforma, no como fila** · backup `.zip` con credencial de admin en el docroot (CWE-312/538) · `wp_salt()` **descarta** el placeholder de `wp-config.php` y usa claves de `wp_options`: leer el config solo da la respuesta **invertida** · `wordpress_logged_in` **no autentica** (medido: sola → 302) · dos superficies de enumeración **se contradicen** (`?author=` ve más que REST) · WordPress **se autoactualizó 6.5.4 → 7.1.2** en pleno engagement · `uid=33(www-data)` → `uid=1001(rafa)`; root **no** alcanzado (`debugfs` sin device node) | — |

**26 of 32 have no `FLAG{}`**, reported as a measured absence with the search that
established it. A reward that is invented teaches the reader nothing about the
finding it is attached to.

[`PILOT-SUMMARY.md`](PILOT-SUMMARY.md) covers the first five as a set.
