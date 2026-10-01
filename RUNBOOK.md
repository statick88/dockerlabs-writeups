# RUNBOOK — from cloning a lab to a rule in the methodology

One repeatable procedure, built from 52 engagements. The per-lab detail lives in
[`corpus/`](corpus/INDEX.md); this file is the path between them.

**Who this is for.** Someone starting an engagement — DockerLabs, a client, a CTF
— who wants the order of operations, and wants to know which steps are load-bearing
and which will quietly lie to you.

**How to use it.** Run stages 0–9 top to bottom. Stages 3, 4 and 6 are where the
time goes and where the wrong answers come from. Stage 8 is the only one that
produces a deliverable; everything before it produces an assumption.

---

## Quick path

```bash
# 1. get it      (no resume on this CDN — one shot or restart)
tooling/download-labs.sh fetch <id>
# 2. deploy      (never run auto_deploy.sh; it never returns)
unzip -oq dist/<slug>.zip -d labs/<id>
docker load -i labs/<id>/<slug>.tar
docker run -d --name <slug>_container <slug>:latest
IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' <slug>_container)
# 3. read the source BEFORE attacking            <- 60% of the lab, decided here
docker exec <slug>_container sh -c 'cat /app/server.js'   # or the compose + entrypoint
# 4. id first, control positive first, in that order
docker exec <slug>_container id
# 5. TEARDOWN — mandatory, the moment the lab is done. Images are 400-800 MB
#    and six idle labs held simultaneously is several GB of nothing.
#    Scope it to THIS lab by name. NEVER `docker system prune`,
#    `docker image prune -a` or `docker volume prune` — the cybervault-*
#    containers belong to another project and a global prune destroys them.
docker rm -f <slug>_container
docker rmi <slug>:latest
# 6. record what the lab taught BEFORE moving on, while it is still fresh:
#    a new instrument defect goes to method/self-corrections.md, a new
#    retrieval hazard to method/retrieval-hazards.md, a new engagement
#    criterion to PenTestMethodology sections/, and the state files
#    (.progress, .agents) get updated. A lab resolved and not written down
#    is a lab that will be re-learned wrong.
```

## The loop

One lab is not a task, it is a cycle:

```
fetch -> deploy -> read source -> recon (control first) -> resolve
      -> writeup + evidence -> TEARDOWN -> feed the methodology -> next
```

The last three steps are the ones that get skipped, and they are the only ones
that make the next lab cheaper than this one.

Full procedure below. Worked examples: [`INDEX.md`](INDEX.md).

---

## The ten stages

| # | Stage | Done when | Fails if you skip it |
|---|-------|-----------|----------------------|
| 0 | Pick by class | The target's class is absent from the methodology | You solve a class you already have |
| 1 | Get it | `unzip -tqq` passes | A truncated archive deploys and wastes an hour |
| 2 | Deploy | `docker ps` shows it up, IP reachable | — |
| 3 | **Read the source** | You can name the sink before touching the app | You fuzz what you were handed |
| 4 | **Recon** | Surface, versions, and every listening socket | You treat a blind spot as an absence |
| 5 | Find the class | The class matches one in the catalogue below | — |
| 6 | **Chain it** | `id` measured at each hop, positive control green | You report a chain you never executed |
| 7 | Prove it | The finding survives its own negative control | You file a bias shaped like a result |
| 8 | Report | Three separate lists written | Findings, controls and tooling defects merge |
| 9 | Restore | `docker rm` + `docker run` from the image, re-verified | The next engagement inherits your artefacts |
| 10 | Feed forward | The class is in the methodology, or explicitly deferred | The work stays in a writeup nobody reads |

---

## 1. Get it

| Constraint | What it does to you |
|---|---|
| **No HTTP Range** | A partial download is unrecoverable. `-C -` fails outright. Every attempt restarts from zero. |
| **Filenames are not predictable** | `spain` ships as `.tar`, `Baremetal.zip` is capitalised, `pingupenguin.zip` is not. Read the real URL from the lab's own page; never construct it from the label. |
| **`exit 0` is not evidence** | Verify the archive (`unzip -tqq` / `tar -tf`). A truncated transfer can still exit clean. |
| **Timeouts are 4–8 min** | `DL_TIMEOUT=3600`, and abort on low speed (`--speed-limit 2048 --speed-time 120`) so a stalled transfer costs 2 min, not an hour. |

## 2. Deploy

```bash
docker load -i labs/<id>/<slug>.tar          # may be several images — check
docker run -d --name <slug>_container <slug>:latest
IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' <slug>_container)
```

**Never run `auto_deploy.sh`.** It ends in `while true` and never returns. It is
also the only place the real topology is written down — **read it, don't run it**:
it names the networks, the `macvlan --internal` segments, and how many containers
the lab wants.

Confirm segmentation before you pivot through it, and confirm the operator's own
containers are not in the way. A lab that expects four hosts and silently gives you
one costs more than a failing deploy.

## 3. Read the source before attacking

This is the single highest-yield step and it is **free**.

**The target may change under you.** Lab 108 shipped WordPress 6.5.4 and, roughly
thirteen minutes in, read 7.1.2 — `wp-cron.php` auto-updated core because nothing set
`AUTOMATIC_UPDATER_DISABLED` and the container reaches `api.wordpress.org`. Pin the
shipped version from the image (`docker run --rm --entrypoint sh <image> -c '…'`) so no
request can fire cron, and record both numbers: they mean different things. A second
reason to read the source early — a `grep` that disagrees with an earlier one may not be
a bug in the tool.

| Read | Answers |
|---|---|
| `entrypoint.sh`, compose, CMD | How many services, as which user, with what flags |
| Route handlers | The real sink, and its middleware **registration order** |
| `sudoers`, ACLs, `authorized_keys` | The escalation surface, read off the file |
| Advisory tables (`import`, `spring-configuration-metadata.json`) | Scope in minutes instead of an afternoon |

**Registration order beats middleware presence.** In lab 146 the admin route was
guarded by a correct `requireAdmin` — on three siblings. The fourth route was
declared **29 lines above** `router.use(requireAuth)`, so the gate never reached it.
No status code distinguishes the two; the source does, in seconds.

**Read the version-bearing config in the artefact**, not from memory. A CVE range
you recall is a guess; the `package.json`, the `MANIFEST` field or the image's
metadata is the fact.

## 4. Recon

`nmap -p-` is **TCP**. That is not a footnote; it hides entire classes.

| Surface | How it hides | How you find it |
|---|---|---|
| Management plane on UDP (BMC, IPMI `623/udp`) | Invisible to `-p-` | `/proc/net/udp`, the image's `ExposedPorts`, a live protocol exchange |
| App behind a **renamed** path | `/admin` returns nothing | Read the rewrite rules |
| A host only reachable through a pivot | `nmap` through a misconfigured SOCKS **scans your own workstation** | Check where the tunnel actually points before trusting the scan |
| A port "closed" by a knock | `filtered` | The knock itself, as the positive control |

**Virtual hosts:** normalise the body, hash it, and include a name that **cannot
exist** as the control. One hash across many names means the baseline. In lab 65,
sixteen names shared one hash — including an invented TLD — and the real admin was
two levels deeper than the name a flat wordlist finds.

**Always run the trípleta before you report anything:**
**reachable → what the body carries → decisive.** A scanner answers the first.

## 5. Class → entry criterion

| Class | The question that starts it | The discriminator |
|---|---|---|
| File upload | Does the filter read `mimetype` (a client header)? | Three axes server-side, **one** browser-side |
| XXE | Does the parser resolve external references? | Return a file value **you know in advance** |
| SSTI | Which field reaches the template? | `{{7*7}}` positive control **first** |
| SQLi | Does the filter prevent or detect? | Two payloads, same filter property, **different** execution result |
| JWT | Does the header carry a key selector? | Empty-key case, **before** any cracking |
| Reversetreff | Is there a KDF in the import table? | The **absence** is the answer |
| Privilege escalation | What does each hop execute as? | `id` at every rung |
| Race condition | What sits between the check and the act? | A serial control that contrasts |
| Container | Privileged? socket? capabilities? identity? | `/proc/self/status`, measured inside |
| Credential attack | Is there a rate budget? | A ladder of rates against a latency baseline |
| Cron / scheduled job | Can you write what it executes? | A marker in a location only its owner can write |
| **IDOR / BOLA** | Does the lookup by request id carry an **ownership** predicate? | Three byte-distinguishable cases: no session → unauthenticated; my session, their object → IDOR; unknown id |
| **WAF / filter** | Is the filter a **string match** or a **scoring engine**, and is the request **body** even inspected? | A string filter is beaten by an unlisted encoding. A scoring engine is not — it has nothing unlisted to reach for. The gap that survives both: **the filter scores each variable independently while the sink composes them** |
| **WAF attribution** | Which component blocked me, and how would I prove it? | A PHP filter gives you two distinguishable bodies. **ModSecurity's block page is Apache's stock 403, unbranded and not byte-stable** (it embeds the Host it refused) — so neither status nor hash identifies the rule. Use the **error/audit log** |
| **CSRF** | Is there a state-changing request that proves it came from the issuing page? | A token that is **emitted but never validated** is not a control. Prove the token rejects *and* accepts. |
| **Cache deception** | What is the cache key, and what does the origin route on? | A response stored for identity A and served to identity B. Prove the cache stores before you read a miss as evidence. |
| **Open redirect** | Does a request value reach a `Location` such that the `Location`'s **origin is not fixed by the server**? | Ask what **consumes** it. With no chain it is a phishing enabler and nothing more (`C:N/I:N/A:N`). A filter's existence is not a control — the corpus's only two filtered handlers both fire and both are bypassed |
| **Mobile / APK** | What does the manifest *claim* is unreachable? | On `targetSdk≥31` an explicit `exported` was **typed by the author**, not inherited — so it is a decision, not a default |

## 6–7. Chain and prove

Three rules, in this order, every time:

1. **`id` first**, inside every new primitive, **as the identity** — not as root.
   The execution identity decides hop count, severity and root cause at once.
2. **Positive control first.** A control that has never seen a success is not a
   control. Run it before you believe any negative.
3. **Prove the negative too.** Read a file as each identity and compare. The
   control that fires and reports itself as an ordinary failure — a `Permission
   denied (publickey,password)` that is byte-identical to a wrong key — is the
   reportable half.
4. **If the vector has no oracle, manufacture one.** Some escalations are silent;
   a silent one cannot be reported as a result. See the next section.

Full catalogue of instrument failures:
[`method/self-corrections.md`](method/self-corrections.md).
False negatives by class: [`method/retrieval-hazards.md`](method/retrieval-hazards.md).

## When the vector has no oracle

Most findings have an **oracle**: you exploit, the effect is visible, you are done.
Some escalation vectors have **none** — and reporting them anyway is how a
non-finding becomes a claim.

| No oracle | Why | Manufacture one |
|---|---|---|
| A cron job that runs a script you can write | It runs, silently, as root. Nothing echoes back. | Write a **uniquely-marked file into a path only root can create**, then wait for its appearance |
| A setuid binary with no output | Success is a state, not a message | Read the artifact you expect to change; if the file exists with your marker, that *is* the result |
| A writable config a service re-reads | The reload looks identical either way | Change a value you can observe from outside the trust boundary |

**The rule: when the vector has no oracle, build the oracle before you exploit.**

Do not report "this cron job runs my script as root, therefore I would be root."
That is a claim about the future dressed as a result. Write the marker, wait,
and point at the file. The witness must be **distinguishable by design** — a
timestamp, a random token, a path the unprivileged user cannot reach — otherwise
you cannot tell your own artefact from a pre-existing one.

This is the same discipline as a positive control, aimed the other way: there, you
prove the detector can fire; here, you prove the payload did.

## 8. Report

Three lists. Never merged.

| List | Contains | In 27 labs |
|---|---|---|
| **Findings** | Bugs, with CWE, literal evidence, impact, root cause, fix | the deliverable |
| **Controls that held** | What resisted, each with a positive control | often more valuable than the chain |
| **Instrumentation defects** | Your own failures that looked like results | 10 catalogued, all shipped-shaped |

Also, and separately:

- **A finding you did not use is still a finding.** Ten of Zabbixploit's were.
- **A privilege escalation that did not work is its own finding.** Lab 129 filed
  key injection (worked) and root (did not) separately, because merging them tells
  the client they patched something.
- **Report the graph of reach, not the tunnels.** The tunnel is a means.
- **State what you did not test, separately from what you discarded with a reason.**

## 9. Restore

```bash
docker rm -f <slug>_container
docker run  -d --name <slug>_container <slug>:latest   # from the image, not by undoing edits
```

Recreating beats reverting. Verify the restore with a **positive** check — the
service answering again, a counter returning to its shipped value. And confirm you
did not leave artefacts elsewhere: `/tmp` is the usual one, and a **file another
principal created is not yours to delete.**

## 10. Feed forward

Before writing anything into the methodology, check the row in
[`INDEX.md`](INDEX.md). Then:

- Class already covered → **extend it** with the new case. An existing rule that
  survived a fresh case is stronger than a new rule with one.
- Class absent → new section, justified against the existing headings.
- Both → nothing. Density beats coverage; four of the last five labs' classes
  already existed and were correctly not duplicated.

---

## Template — a new lab's step-by-step

Copy this into `corpus/<id>/`. Fill every field. An empty field is a finding you
did not look for.

```markdown
# <ID> <Name> — writeup

## Surface
nmap -sV -Pn -p- <IP>  → <verbatim>
Stack and versions: <from the artefact, not from memory>
Hidden surfaces found: <and how>

## The class
Entry criterion: <the question that started it>
Source that settled it: <file:line>

## Chain
| # | → | Mechanism | Identity proof |
|---|---|-----------|----------------|
| 1 | <user> | | `uid=` |

## Findings
<one per finding: CWE, literal evidence, impact, root cause, remediation>

## Controls that held
| Control | Positive control that proves this detector works |
|---|---|

## NOT tested vs discarded with reason
<two separate lists>

## Instrumentation defects
<what lied to you, and what caught it — the most valuable section>

## Reward
<the literal value, or the search that proved its absence>
```

---

## Checklist before you call an engagement done

- [ ] Source read before the first request
- [ ] `id` measured at every hop, as the identity
- [ ] Every detector has a green positive control
- [ ] At least one negative proven
- [ ] Surface recon covers what a TCP scan cannot see
- [ ] Findings, held controls, and instrumentation defects written separately
- [ ] Not-tested separated from discarded-with-reason
- [ ] Lab restored from the image and re-verified positively
- [ ] Rule checked against `INDEX.md` before writing
- [ ] **Documentation-only changes classified passive by review are not a content
      review** — the two CRITICAL defects in this corpus were both found by an
      adversarial audit, and neither would have been visible to a reader

## Next step

[`corpus/HOW-IT-WAS-RESOLVED.md`](corpus/HOW-IT-WAS-RESOLVED.md) — how all 45
engagements were actually resolved, with the discriminator that settled each one.
[`INDEX.md`](INDEX.md) — find your class, read that writeup, check the heading the
row names.
