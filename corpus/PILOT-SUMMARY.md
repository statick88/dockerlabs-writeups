# Pilot Summary — five DockerLabs engagements, what each contributed, and what repeats

**Scope:** five lab engagements against DockerLabs, run as a pilot to test whether a pentest methodology repository earns new oracles from real engagements or merely accumulates prose. Each lab produced a full writeup with literal evidence, an independent-findings section, and an explicit "tested / not tested / could not test" split.

**Labs:** Asturias (Express, unauthenticated backup by middleware ordering) · Acme (WordPress bastion, credential in a pre-auth banner) · PipePwned (Flask + CI/CD, SSTI to runner root) · Zabbixploit (Alpine + Zabbix 3.0.3, SQLi to remote command) · BaluHome (Node/Express video platform, stored XSS to root cron).

---

## 1. What each lab contributed

| Lab | Bug class that was new to the repository | Oracle that survived into the repo |
|---|---|---|
| **Asturias** | Unauthenticated access arising from **registration order** — a route declared above its module's `router.use(requireAuth)`; plus CWE-434 upload reaching `require()` | Backup/bulk-export rule (anonymous request + protected-sibling control, spec-vs-behaviour asymmetry, WAL sidecars) |
| **Acme** | **Pre-authentication channel disclosure** (SSH `Banner`) and **world-writable document root** as a code-drop primitive needing no application exploit | Banner-is-public-by-specification rule; world-writable docroot rule; "measure the execution identity of your RCE" |
| **PipePwned** | **SSTI**, with the two-parameter differential oracle | SSTI oracle (same payload to a source-reaching field and a context field in one request); `## CI/CD Runners` prose section |
| **Zabbixploit** | **Per-column SQL injection** in a hand-built statement; **session hijack proven by predicting a server-derived value**; **dispatch status ≠ execution** | Per-column escaping oracle; error-oracle length verification; session-hijack prediction; `## Monitoring Agents` prose section |
| **BaluHome** | **Upload served in-origin as an active content type** (a fourth upload axis, no template sink involved); **XSS severity determined by a cookie attribute**; **session-secret signature forgery**; **a setuid interpreter that discards the privilege** | Fourth upload axis; rate-an-XSS-by-cookie-attributes; session-secret recomputation oracle. One section **proposed, not created** (§4). |

Roughly 15 oracles exist across the two files. **Four of the five labs contributed at least one durable rule; every one of the five produced findings that were not needed for the solve and were reported anyway** — PipePwned's world-readable token, Acme's unused `sudo NOPASSWD`, Zabbixploit's ten findings including an allowlist that *worked*, BaluHome's hardcoded secret and in-origin upload.

---

## 2. The pattern that repeats: self-documentation

**Five out of five. This is a law, not a coincidence.**

| Lab | What the target shipped about its own weaknesses |
|---|---|
| Asturias | `CWE-434` in a comment; a `SCRIPT_EXTENSIONS` constant naming the exploit path in a variable |
| Acme | `# Banner with credential hints for Nmap` |
| PipePwned | `# TODO: service runs as root` |
| Zabbixploit | `EnableRemoteCommands=1` named in config as the deliberate failure |
| BaluHome | **a 223-line README containing four named CWEs, the bot's design, the full escalation path, and a numbered 14-step attack chain** |

The progression is worth noting because it sharpens the risk. Asturias labelled one bug. BaluHome shipped the entire solution document — and drew the line in a genuinely thoughtful place, keeping every hint out of the rendered interface and putting the documentation on the attacker's *filesystem* rather than in their *traffic*.

**And in every single case the spoiler was strictly smaller than the target.** That is the finding, and it is stronger than "labs are self-documenting":

- Asturias labelled the CWE but not the middleware registration order — which is not observable from outside the application at all.
- Acme labelled the banner but not the `777` document root, and the agent found 2 hops where it had planned 3 (php-fpm ran as root).
- Zabbixploit named the misconfiguration whose *named* vector (port 10050) was blocked by a correct allowlist — the label pointed at the working control.
- BaluHome documented four vulnerabilities and shipped an unlabelled upload path, an unlabelled hardcoded session secret, and a documented final escalation step that **cannot work on the image it ships**.

**Candidate transversal rule for `decision-making.md`:** extend §7 from *a label confirming your hypothesis stops the derivation* to also cover *a complete write-up of the intended chain stops it just as effectively* — because both end with a confident-looking document and a green checkmark, and nothing downstream can distinguish a lab that hands you the answer from one that makes you find it. The corollary for the reader is the same as §7's: the source of a running application is the highest-fidelity **intent** source available and the lowest-fidelity **reachability** source, because comments mark where a problem was *admitted*, which is a strict subset of where problems *are*.

---

## 3. The pattern that repeats: the name is narrative, not evidence

**Five out of five, and in the last three the name actively pointed the wrong way.**

- **PipePwned** — named for Windows named pipes; it was a Linux Flask application with CI/CD. The mismatch was not subtle and cost a hypothesis.
- **Zabbixploit** — the vector the name announced (agent on 10050) was blocked by a correctly configured allowlist. The agent followed the name, hit a working control, and had to work backwards to the real bug.
- **BaluHome** — named for home automation; it was a YouTube-style video platform. No MQTT, no Zigbee, no hub, no automation protocol of any kind.
- Only Asturias and Acme had names that were merely unhelpful rather than actively misleading.

The instance that generalises best is BaluHome: one `nmap -p-` showing a single Express port and one `GET /` would have retired the smart-home hypothesis in under thirty seconds. **The port table is evidence; the name is marketing.** This is arguably already implicit in `decision-making.md` §7's "derive the sink, never look for the label" — the pilot's contribution is that the *lab name* is one more label, and the most seductive one, because it arrives before any observation and therefore feels like a hypothesis rather than a conclusion.

---

## 4. The pattern that repeats: the most valuable finding is often a control, an error, or the documentation itself

This is the pattern I would weight **highest** for a transversal rule, because it recurred in all five and because it is the one the repository's structure handles worst — a repository of techniques naturally files "a control worked" and "I made a mistake" as footnotes.

**(a) Controls that worked.** Zabbixploit's `allowed_hosts` allowlist blocked the lab's named vector, and the *daemon's own rejection log* was the evidence that identified the control. Acme's `require()` path was never reachable because the docroot permissions were worse than the application bug. BaluHome's `requireAdmin` returned real `403`s on both privileged routes, its `path.extname` genuinely blocked traversal, its `execFileSync` array form blocked command injection, and its graceful `try/catch` around `ffmpeg` removed the last chance for an accidental type check to reject a malicious upload. **None of these was a footnote in any of the three writeups.** The `infrastructure.md` `## Monitoring Agents` section exists because of the first one.

**(b) My own errors, which were the most instructive findings in three of five engagements.** Zabbixploit: an error-based SQLi oracle silently truncated a 32-character secret to 31, and the resulting rejected cookie looked exactly like a session-store incompatibility — it nearly sent the whole chain down the wrong path. BaluHome: a hand-transcribed cookie signature produced a 34-of-43-character "mismatch" that read like a wrong key and would have made me discard a real hardcoded-secret finding; a `grep -q rootbash` existence detector that matched its own error message and reported success on a file that did not exist; and a `sed -i` that failed because the group grant was on the file and not on its directory. Acme: an assumed three-hop chain that turned out to be two. **Each of these became a rule, and none of them was a bug in the target.** The pilot's clearest methodological yield is that the hardest part of this work is instrumenting the *tester*, and the repository currently has no place to file that.

**(c) The documentation itself.** BaluHome's README prescribes `cp /bin/bash /tmp/x && chmod u+s /tmp/x; /tmp/x -p` as its final escalation. A shell discards an elevated effective uid at startup — `bash` and `dash` both do it independently — so the step cannot work on the image that ships it. I proved the escalation is nonetheless real (direct root execution through the group-writable root-executed script, `uid=0(root)`, verified by reading a mode-700 directory), and localised the failure to the interpreter rather than to the container: `nosuid` absent, `NoNewPrivs: 0`, `CAP_SETUID` present in the bounding set, and a setuid copy of a **non-interpreter** returning `euid=0(root)`. A target's own instructions containing an impossible step is a reportable defect in its own right, and it is invisible to any methodology that only records what worked.

**Candidate transversal rule:** *report three lists, not one — findings in the target, controls in the target that held, and defects in your own instrumentation.* The second and third are where the transferable knowledge is, and both are systematically under-reported because neither produces a green checkmark on the target.

---

## 5. Recommendation

I would add **two** rules to `decision-making.md`, both narrow and both falsifiable:

1. **Extend §7 by one sentence** to cover a complete solution document as a stopping condition, not only a single confirming label (§2 above). Cheap, and it generalises across all five labs.
2. **Add a rule requiring the three-list report** — target findings / controls that held / tester-instrumentation defects — with the rule that a control which held is reported with the same prominence as a bug that fired, and that a partial agreement in a cryptographic comparison is evidence about the comparison rather than about the key (§4 above).

I would **not** add a new "read the lab name sceptically" rule: it is already §7's "derive the sink, never look for the label" wearing a different hat, and a fifth repetition of an existing rule is a reason to *sharpen* §7, not to grow the file.

One section is **proposed and not created**, per the standing instruction: `## Setuid and Trusted Executors` in `infrastructure.md`, whose class has no oracle anywhere in the repository (setuid/suid/euid appear only as bare wordlist bullets under `### SUID`). Its content is drafted in `BALUHOME-WRITEUP.md` §12.

---

## 6. Provenance

- Writeups: `ASTURIAS-WRITEUP.md`, `ACME-WRITEUP.md`, `PIPEPWNED-WRITEUP.md`, `ZABBIXPLOIT-WRITEUP.md`, `BALUHOME-WRITEUP.md` (this directory).
- Repository edits: `sections/api_web.md` (fourth upload axis, XSS-severity-by-cookie-attribute rule, session-secret signature oracle), `sections/infrastructure.md` unchanged in this engagement (the group-writable trusted-executor class was already covered by `## CI/CD Runners`; duplicating it would have been repetition, not density).
- No target credentials, tokens, cookies, hostnames, or reward strings are present in any repository file; four pre-existing work units were left uncommitted and intact.
- Every technical claim above is traceable to a literal command output preserved in the corresponding writeup and evidence directory.
