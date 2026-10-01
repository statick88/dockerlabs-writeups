# DockerLabs writeups

The evidence corpus behind the decision layer in
[`PenTestMethodology`](https://github.com/statick88/PenTestMethodology).

60 lab engagements, resolved and audited (plus 2 recorded as unobtainable). This repo holds **what
happened**. The methodology repo holds **what to conclude next time**. They are
separate on purpose: the methodology has to stay portable and citable, and the
evidence has to stay specific and unedited by summary.

## Why they are separate

The methodology cites cases as `file:line` so a future reader can re-verify a
rule. Those citations only mean anything if the evidence they point at actually
exists somewhere. Keeping the evidence in its own repo makes the citation
resolvable instead of aspirational, and it stops a writeup's prose from being
edited into agreement with a rule that later changed.

**What "resolvable" means here, precisely — and where it stops.** A methodology
citation now lands on a writeup you can open, and the writeups quote the
decisive artefact lines verbatim. That is a real gain over a private corpus. It
is **not** artefact-level re-verification: this repo holds **no** lab artefacts,
so of the 1354 `file:line` citations across the corpus, **zero** can be resolved
by a reader without the archive. Three of the four auditors in the first
adversarial pass reported this independently, and it is the reason the historical
CRITICAL class — a citation that does not say what it is cited for — is
*structurally* invisible to any review here, including the native one, which
classifies the whole corpus passive.

So: a reader can check the **reasoning** and the **quoted evidence**. A reader
cannot independently re-run the target. Treat the writeups as a transcript, not as
a reproduction, and re-fetch the archive when a claim is load-bearing enough to
dispute.

## Layout

```
RUNBOOK.md                   the procedure, cloning to methodology  (start here)
INDEX.md                     engagement → class → methodology rule
PIPELINE.md                  the two-lane operating plan (start here to work the queue)
corpus/<id>/                 one writeup per lab, plus raw evidence artefacts
corpus/HOW-IT-WAS-RESOLVED.md  every lab: class, discriminator, reward (start here)
corpus/INDEX.md              the labs, their class, and their reward
corpus/PILOT-SUMMARY.md      the first five, written as a set
method/self-corrections.md   the failures that recur across all 27
method/retrieval-hazards.md  how a scanner confidently reports nothing
tooling/download-labs.sh     standalone fetcher, no agent required
tooling/labs.manifest        the work queue, with the reason each lab was picked
tooling/README.md            how the platform behaves
```

**Two entry points, depending on what you are doing.** If you are **running** an
engagement, open [`RUNBOOK.md`](RUNBOOK.md) — it is the whole arc, cloning through
deployment, recon, chain, proof, report, restore, and feeding the methodology
forward, with the load-bearing steps marked and a template for the writeup. If you
are **looking for something specific**, open [`INDEX.md`](INDEX.md) and go straight
to the class.

## Using it for another project

The corpus is DockerLabs. The method is not.

1. **`method/` is the transferable part.** `self-corrections.md` is a catalogue
   of instrument failures that have nothing to do with this platform — a
   `test -w` run as root reports a different answer on any target. Read it before
   trusting any negative in an engagement.
2. **`INDEX.md` is the map.** Find the row whose class your target has, read that
   writeup, and check what the methodology says at the heading the row names. The
   headings are the stable reference; line numbers are a convenience and will drift.
3. **`tooling/download-labs.sh` is platform-specific** and will not help elsewhere,
   but the constraints it encodes are general and worth stealing: no resume, verify
   the archive rather than trusting the exit code, and read the real URL from the
   page instead of guessing the filename.
4. **Add a corpus, not a rule.** A new engagement goes in `corpus/`, and a row in
   `INDEX.md`. The methodology changes only when a class turns up that it does not
   already have.

## What every writeup contains

Findings with CWE and literal evidence, a control test with a **positive control**
for each oracle, the chain with the order and the reason for each hop, a
**self-correction section** — which is the part worth reading — an explicit split
between *not tested* and *discarded with a reason*, and the lab-design observation
if the target had one.

## Rewards

Twenty-two of the twenty-seven have no `FLAG{}` or equivalent. That is reported as
a measured absence with the search that established it, not filled in. A report
that invents its own reward teaches the reader nothing about the finding it is
attached to.

## Discipline this corpus ran under

No commit and no push without explicit instruction. Documentation-only changes are
classified **passive** by the native review, which approves the *classification*
and does not read the content — so a separate adversarial content audit runs on
every batch. That audit found the only CRITICAL defects in the programme, including
a false stack-frame derivation inside the section titled *"read the sink, do not
guess the offset"*. Neither was visible to the native review, and neither would
have been visible to a reader.
