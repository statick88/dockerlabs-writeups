# Self-corrections — the failures that recur

Twenty-seven engagements produced one dominant failure shape, and it is not a
missing technique. It is this:

> **A measurement that is wrong looks exactly like a result.**

Every case below produced well-formed output. None of them errored. Each would
have shipped, and several of them would have been filed to a client as a finding
or as a negative result. They are ordered by how much they cost.

---

## 1. The positive control that had never seen a success

Lab 118, credential attack. The agent's own control script had port 22 hardcoded
and was talking to **the host's sshd, not to its control container**. It was about
to certify **17,000 negatives** from an instrument that had never once observed a
success.

What caught it was noticing the sweep contradicted a file already fetched in the
same session.

**Rule.** A control that has never seen a success is not a control. Force a
positive through it before believing any negative it produces.

## 2. Privileged tooling contaminating the measurement

Lab 141 and lab 129, independently. `test -w` reported **WRITABLE** because the
command ran through `docker exec`, which is root. The predicate was correct; the
identity was wrong.

Lab 129's companion: a `chmod` in a permissions table that ran **on the operator
host**, where the container's path does not exist. Five rows reported `LOGIN OK`
and one `DENIED` — all six re-testing the same unmodified file — while
`No such file or directory` scrolled past unexamined.

**Rule.** Every control runs as the identity whose capability you are measuring. A
privileged tool does not observe a low-privilege boundary; it observes itself.

## 3. The harness is the outage

Lab 238. A blocking `execSync` whose `curl` called back to the **same** Express
process deadlocked its own event loop. From outside, the app went silent — while
`/json/list` on another thread of the same PID still answered `200`. The agent
read it as prototype pollution, because that was recent and had a CWE.

Refuted on a clean instance: the control to a different process answered in
0.97 s, and the treatment raised its own `-m 8` timeout at exactly 8.05 s. The
app recovered on its own once the deadlock released.

**Rule.** *Process alive* is not *service serving* is not *message executed*.
Replay the most recent action on a clean instance before theorising. Every payload
sent through an injection primitive needs its own timeout.

## 4. Your own rate limit, wearing a false negative

Lab 283. The agent's own rate limiter made a working injection return `False`. It
read as *the injection is dead*.

Also lab 283: `urlencode` **double-encoded** a value that was already encoded, so
its "encoding bypass" test was measuring its own encoder.

**Rule.** Your concurrency above the target's makes every negative false. And
check your own encoder once before you attribute a failure to the target.

## 5. Binary search over a non-monotonic predicate

Lab 283. The predicate "does this character match" is not monotonic, so binary
search returned **`~~~~` for every character**. `~~~~` is the signature of a broken
search, not a password — and the agent nearly filed it as the administrator's
credential.

**Rule.** A search that returns the same value everywhere has failed, whatever that
value is. A uniform answer is a result about the search.

## 6. Oracles that cannot fire

Lab 90. A conditional oracle whose condition sat in a malformed `ON` clause, so it
**short-circuited to one side every time** and only one derived table ever
materialised. Four shards printed `NOTFOUND` having examined **zero lines**.

Lab 36. The yescrypt scanner read field `[1]` of the **first** line of
`/etc/shadow` — which is `root`, whose field is `*` — so `crypt()` returned `*0`
**without ever executing the KDF**. The tell was the rate: `10705.7 candidates/s`.

**Rule.** An oracle that always resolves the same way is a bias wearing the shape
of an answer. The positive control runs **first**, not after. And when a
cryptographic step finishes implausibly fast, the step did not run.

## 7. A tool that summarises, giving you the wrong reading

Lab 238. The environment's `docker logs` wrapper **truncated and summarised** the
application's request log, and the agent drew a conclusion from the summary. Reading
the raw stream with `PATH=/usr/bin:/bin` gave a different account.

A container-management wrapper is a filter, and a filter is an instrument. Read
raw output before you reason about it.

## 8. Control flow, and what actually executes

Lab 23, Spain. A self-test asserted the payload was free of `0x00` bytes. **It
passed**, and the payload still mis-executed — `0x40` is `inc eax` in 32-bit mode,
not `inc ecx`, so the shellcode called `getppid` where a `dup2` belonged.

**Rule.** Assert what the consumer *does with* the bytes, not what the bytes *are*.
The self-test must decode and assert the syscall arguments, and emulate the stack
string.

## 9. Truncated and complete look identical

Lab 163. An arbitrary cap cut a wordlist sorted punctuation-first, where the real
words sit at index ~105,000. The sweep reported 2 of 7 present files. **A truncated
sweep and a complete sweep print identically.**

**Rule.** Cross-check the sweep against an artefact you already fetched. Output
shape is not evidence of coverage.

## 10. The filter that was correct, and the host that was not

Lab 146. The upload handler allowlisted one extension, forced `uniqid().".jpg"`, and
trusted `originalname` not at all. It was **correct**. The RCE came from a global
`AddType application/x-httpd-php .jpg` in the main server config, outside every
`<Directory>`.

The lab shipped three directives that "explained" the behaviour. **Two were inert**
— and the one that named the exact behaviour, a root-owned `.htaccess`, was the
dead one. Proven with three states: original file → executes; replaced with
`Require all denied` → executes; **deleted** → executes.

**Rule.** Patching the handler ships nothing. Read the server's content-type →
handler map, and check whether the directory's `AllowOverride` even lets a
per-directory file speak.

---

## The pattern underneath

Six of the ten above are a single sentence: **the instrument, not the target,
produced the answer.** Two more are the instrument producing a *confident
negative*. The remaining two are the instrument reporting faithfully about
something other than what was asked.

The unifying discipline is already written into
`decision-making.md` as *a self-test validates the tool, not the trace* — and
these are the instances that made it concrete. The corpus is the receipt for that
rule; this file is why the rule exists.
## 11. A tool that does nothing, and exits 0

`find -writable` does not exist in busybox. It printed its usage text, returned
nothing, and **exited 0** — so a "no writable critical files" negative looked
clean, and the entire privilege-escalation finding was one `test -w` away from
being deleted. `test -w` disagreed at the same instant.

This is worse than "command not found". A missing command is visible; a command
that succeeds while doing nothing manufactures a negative that *confirms what
you hoped*. **Rule.** Any negative that comes from a bulk enumeration gets one
independent confirmation from a different tool, in the same shell, before it is
recorded. Compare the tools' answers; do not average them.

**Related: an alias for a real thing.** `ls -l` prints a size column that looks
exactly like a mode. `777` read as "world-writable" when the mode was `664` and
the file was `root:pinguinos`. The finding survived; the stated mechanism was
wrong. A wrong mechanism in a report is a wrong report.

## 12. A second tool that reads nothing, and exits 0

`strings -a` on a binary `AndroidManifest.xml` returns **nothing** — the string
pool is UTF-16, and the default scan is ASCII. An analyst running only the
obvious command concludes the manifest is clean: no components, no permissions,
nothing to find. `strings -a -e l` finds them all.

Same failure as #11, different surface: the tool is not broken, it is being asked
the wrong question, and it reports the empty answer with a zero exit status. A
tool that returns "I found nothing" has made a claim about the world, not about
itself. **Rule.** Before recording an absence, confirm the tool can *find the
thing you expect to exist*. Point it at a string you know is present. If it does
not come back, the tool is the problem.
## 13. A client that follows redirects, turning every auth test into a 200

Python `urllib` follows redirects by default. A test that meant to read
`GET /dashboard` without cookies returned **200** — because the unauthenticated
request was redirected to the login page and the login page returns 200. Every
such test agreed, which is exactly why it was dangerous: the detector was
always-true.

The result was the **inverse of the truth**. The finding being tested was
"`wordpress_logged_in` alone authenticates" (it does not — it alone gives 302,
and `pluggable.php:889` requires a live session token). With redirects followed,
the test reported 200 and the cookie looked sufficient.

**Rule.** Any authorisation test must (a) disable redirect following, and
(b) assert on something the error page cannot fake — a final URL, a status you
expect to *fail*, or a body marker. And a negative control that returns the same
status as the positive is not a control; it is a coincidence you have not checked.

## 14. A negative that did zero work

`file('/dev/stdin')` inside PHP returns **0 lines** when stdin is empty. The
harness then reported `candidates=0 matches=0` — a clean, quiet, completely
uninformative negative that would have been filed as "this key does not crack".

The same shape: `find -writable` (§11), `strings -a` on UTF-16 (§12), PHP over
/dev/stdin. **A tool that did nothing and a tool that found nothing produce
identical output.** The difference is only knowable from outside the tool.

**Rule.** Every negative carries its work count: bytes read, candidates tested,
rows returned, files matched. A negative with no count is not evidence, it is
the absence of evidence wearing evidence's clothes. If the count is zero, the
answer is **untested**, and it belongs in the NOT-tested list with the reason.
## 15. A sanitiser that rewrites the language it never validated

`htmlspecialchars` escapes `&` into `&amp;`. `&` is the shell background
operator. The payload therefore returned a **full 200 page, appended zero
bytes, and still cost the full request time** — because PHP's `system()` blocks
on the pipe the backgrounded child holds. It reads exactly like a filter
blocking the input, and the control and the negative differed by **one
character**.

**Rule.** A sanitiser changes the parse of every language it did not validate.
Before trusting an escape, name the second grammar that reads the same bytes. An
output encoder defends an HTML context and is silent about a shell, a SQL, an
LDAP filter and a path. Here the encoding was not a weakness in the app's
*output* handling — it was a bypass of the *input* handling, and nothing in the
response said so.

## 16. `403` is not a verdict, and `test` has no oracle

Two more instruments that answer with silence:

- **Two layers of one WAF returned two different 403 bodies** (hashes
  `a93f0c50cc63` and `c2eb23c5660c`). A status code cannot attribute a block to
  a rule. **The discriminator is the body**, and the positive control — three of
  three blocked operators — has to run *before* any belief about a bypass.
- **`[ -r path ]` is silent in both branches.** False, silent; true, silent
  through `printf`. Both collapse to an empty substitution, so the outer `ls`
  listed **its own cwd** and the result looked like a successful listing of the
  directory that was actually being denied. The same shape as `fail2ban-client`
  reporting `Total failed: 0` beside sixteen real failures, and as `git`
  refusing on `safe.directory` — empty stdout, **exit 0**, which a `| od -c`
  pipeline hides completely.
- **Common root.** These are all §11–§14 wearing different costumes. A tool that
  reports nothing and a tool that has not looked are indistinguishable from the
  output alone. The only reliable discriminator is external: a work count, or a
  second tool that disagrees.
## 17. The harness redirect is parsed on the wrong side

`docker exec <c> wc -l < file` — the `< file` is redirected by the **host** shell,
not inside the container. It printed an error to stderr and returned empty, so a
log-slicing harness reported `loglines=0` for **every** probe.

Believing it would have inverted the headline finding into "the CRS detects
nothing", because the CRS was in fact blocking correctly. The tell was structural,
not numerical: a 403 alone cannot tell you which half of the pipeline lied.

**Rule.** In any two-process pipeline — host into container, client into proxy —
count the work on **each** side independently, and prove both sides carried
something before believing a zero from either. A redirect in a compound command
belongs to the shell that reads it, not the one it is aimed at.

## 18. A control must come from a payload that already worked

"My liveness control" added one character to a working payload and produced zero
log lines, because the one-character variant is not itself a detectable pattern.
The control was not weak; it was **designed from nothing**, so its silence proved
nothing about the thing it was meant to prove.

**Rule.** A control is valid only if it comes from a payload you have *already
seen succeed*. The stronger form used here instead: add a probe parameter and
read the log's per-variable attribution, which shows a **true zero** for the
variables under test and distinguishes it from an untested one — a distinction no
single before/after comparison can make.

## 19. A blank count is not a zero

A shared `/tmp` scratch directory was **deleted by a concurrent worker**, so every
byte count in a batch came back blank. Blank and zero look identical in a
report, and "lab 1 returns an empty body" would have been filed as a measured
property of the application. The real figures were 42 and 60 bytes.

**Rule.** A missing or blank count is **untested**, never zero. Confirm the
scratch path exists before trusting a batch, and write the count next to the
result it belongs to. This is the same root as §11 through §14 and §17: the
output cannot distinguish *found nothing* from *looked nowhere*.

---

## Reading this catalogue

Sections 11 through 19 are not nineteen separate warnings. They are one failure
with nineteen faces, and the corpus keeps producing new ones:

| # | Instrument | What it reported |
|---|---|---|
| 11 | `find -writable` (busybox) | success, empty result |
| 12 | `strings -a` on UTF-16 | success, empty result |
| 14 | PHP `file('/dev/stdin')` empty | `candidates=0 matches=0` |
| 15 | `htmlspecialchars` escaping `&` | 200, zero bytes written |
| 16 | `[ -r ]` silent in both branches | a successful listing of the denied path |
| 16 | `fail2ban-client status` | "in operation", zero of 16 failures |
| 16 | `git` `safe.directory` refusal | empty stdout, exit 0 |
| 17 | `docker exec … wc -l < file` | `loglines=0` for every probe |
| 19 | `/tmp` deleted by a concurrent worker | blank where a count belonged |

**The single rule that covers all of them:** a tool that found nothing and a tool
that has not looked produce identical output. Only an external work count, or a
second tool that disagrees, tells them apart — and a count of zero is itself
evidence that nothing was tried.

Six of the nine would have deleted a finding, three would have invented one. None
of them looked like an error. That is the whole argument for the catalogue.

## 20. A self-referential ordinal is not a measurement

Three separate writeups each asserted they were **"the seventeenth lab in this
series without a `FLAG{}`"** — labs 189, 61 and 87. At most one can be right, and
a fourth said "fifteenth" *after* one of them said "seventeenth", so the sequence
is not even monotonic. The corpus had nine such orderings and no enumeration to
resolve them.

**Rule.** A count is a fact; a *position in a sequence you are inside* is a claim
about the corpus's history, and it rots the moment anything is added. State the
count, or state the property, and point at the index — here, the `FLAG{}` column
of `corpus/INDEX.md`, which is the single source. The same applies to "the first
time we saw X" and "the Nth lab to do Y".

This is the same defect class as §14 and §19 one level up. A tool that returned a
confident answer it did not earn is the recurring failure; a document asserting a
position it cannot compute is the same mistake written down.

## 21. `defined( 'X' )` is not "the framework uses X"

Lab 117 filed a security finding that WordPress' auth cookie key "derives from a
public constant" because `wp-config.php` ships all eight keys as the install
placeholder. It quoted three runtime lines as proof — including
`wp_salt('auth') strlen=128`. **A 33-character placeholder cannot produce a
128-character salt, so the quoted output was already refuting the sentence next to
it.** The two real errors:

- `defined( 'AUTH_KEY' )` is trivially true of any constant. It says nothing about
  which value the framework *consumes*.
- Two values printed next to each other — the constant, then the `wp_options`
  value — were read as a **precedence** relationship. Adjacency is not precedence.

`wp_salt()` (`pluggable.php:2424` in that lab's 6.6.1) pre-seeds a duplicate list
with the literal installer string and **skips** any constant whose value is in it,
so the config value is *ignored*, not overriding. Asking the framework returns the
generated value; asking PHP whether a constant exists returns `true` regardless.

**Rule.** A framework that validates, defaults, or overrides configuration will
routinely ignore a value that is present and well-formed. **Measure the value the
framework consumes, not the value the file contains** — call `wp_salt()`, call
`app.config()`, read the parsed tree. And when a measurement contradicts the
sentence it is placed under, resolve the contradiction in favour of the
measurement before writing the sentence.

Worth noting how it was caught: lab 108 had already tested the opposite and
recorded that its forgery was **rejected**. The contradiction was visible across
two writeups and nobody cross-read them. A rule that survives one lab and is
reversed by another has not been tested — it has been sampled once.
