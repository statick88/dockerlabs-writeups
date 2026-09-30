# PIPELINE — solving labs continuously

The operating plan for clearing the remaining catalog. Two lanes, one queue, and
a state that survives the session ending.

**Not a target: 205 labs.** The catalog is a supply of class gaps, not a backlog
to be emptied. The run converges when a batch stops yielding a class the
methodology lacks — see [Convergence](#convergence).

---

## The shape

```
                    ┌──────────────────────────────────────────┐
  labs.manifest ───►│ LANE A  downloader (background, 3 wide) │
  (class-gap order) │  fetch → verify → .ok marker             │
                    └───────────────┬──────────────────────────┘
                                    │ .ok
                                    ▼
                    ┌──────────────────────────────────────────┐
                    │ LANE B  solvers (foreground, 3–4 wide)   │
                    │  read source → chain → prove → write up   │
                    └───────────────┬──────────────────────────┘
                                    │ writeup
                                    ▼
                    ┌──────────────────────────────────────────┐
                    │ FEED FORWARD  parent, not delegated       │
                    │  class table + self-corrections + INDEX   │
                    └──────────────────────────────────────────┘
```

**Lane A never stops. Lane B starts a solver as each lab lands.** The parent
never waits on a download.

---

## Why two lanes and not more

Measured in this environment, not estimated:

| | Time per lab | Source |
|---|---|---|
| Download | **~6 min** | 108 = 195 MB, 8 min across 2 attempts |
| Solve | **~30–60 min** | four delegated engagements this session |
| Ratio | **1 : 6** | — |

A download consumes **one sixth** of a solve. One serial downloader already
feeds six solvers, so **bandwidth is not the constraint** — solver concurrency
is, and that is bounded by RAM (19 GB free), cores (5), and how many workers a
session can supervise.

**The fetcher is parallel anyway, for a different reason: fault isolation.** The
CDN has no HTTP Range, so one unresumable archive blocks everything behind it.
Id 268 died on four consecutive attempts and cost **~20 minutes** of serial
queue. `DL_PARALLEL=3` keeps three labs in flight so a bad one stalls one third
of the lane instead of all of it.

| Knob | Default | Why |
|---|---|---|
| `DL_PARALLEL` | 3 | Fault isolation. Not bandwidth — 1:6 says bandwidth is fine |
| `DL_TIMEOUT` | 3600 | A 1.2 GB lab at 500 KB/s needs ~40 min |
| `DL_RETRIES` | 4 | Attempt 1 dies often; 108's died at 2m19 |
| Solvers in flight | 3–4 | RAM-bound, not CPU-bound |

---

## The real constraint is disk, not network

**54 GB free.** Each lab costs, transiently and then permanently:

| Artefact | Size | Keep after solve? |
|---|---|---|
| Archive in `dist/` | ~350 MB (50 MB – 1.2 GB) | Re-obtainable; the writeup is the evidence |
| Extracted tar in `labs/` | ~350 MB | No — same |
| Docker image | **~2–3 GB** | Only until the writeup is committed |

≈ **3 GB per lab**, so **~18 labs of runway** before reclaim is required.

### Reclaim policy

| Action | Whose | Status |
|---|---|---|
| `docker image rm` on the image of a lab whose writeup exists | ours | **safe** — the image is re-obtainable from the archive |
| Delete `labs/<id>/` extracted tar after the writeup lands | ours | **safe** — same |
| Delete `dist/<archive>` after the writeup lands | ours | **safe**, but it forces a re-download on a retry |
| `docker system prune -a` / `docker volume prune` | **NOT ours** | **forbidden** — see below |

**Never run a global prune.** Seven `cybervault-*` containers have been running
5 days and belong to a different project; a blanket `volume prune` would delete
its Postgres and Redis data volumes. Reclaim **by image name**, never with
`system prune`. Reclaimable now: 29.45 GB of images, 5.4 GB of volumes — most of
the volumes are not ours.

---

## Queue discipline

`tooling/labs.manifest` is the ordered queue, and it is also the coverage
record — a lab is in it because it fills a gap, with the gap named in the fourth
field. Order is by **gap size, not difficulty**, with *fácil* first inside a gap:
a new class is worth more than a harder lab in a class we already have.

Current gaps, ranked by what they unlock:

| Gap | Labs available | Why it is a gap |
|---|---|---|
| **WordPress** | 12 | A whole platform, and we have one lab (90 Norc) |
| **WAF bypass** | 5 | Evasion exists as a class; a concrete WAF does not |
| **Deserialization** | 2 | Pickle covered (148); the rest is not |
| **LDAP, open redirect, smuggling, GraphQL, prototype pollution, mass assignment, NoSQL, k8s, CRLF, host header** | 1 each | Absent entirely |

**The next 17 are downloaded in the background** and listed in
`labs.manifest` with their gap reason.

---

## Feeding forward is the parent's job, not the worker's

A worker produces a writeup. **The parent** decides what enters the methodology,
because the class table is shared and a worker that edits it in isolation drifts
it — already observed once, when a delegated worker reported an `INDEX.md` row it
had not written.

Per solved lab the parent does, and verifies by **count, never by report**:

1. `corpus/INDEX.md` — one row per writeup, relative link form `<id>/NAME-WRITEUP.md`
2. `labs.manifest` — one `id|Name|difficulty|gap` line
3. `RUNBOOK.md` §5 — add the class if absent, **extend the row if present**
4. `method/self-corrections.md` — add any instrument defect that misled a worker
5. Reconcile: `manifest count == corpus count + 1` (the `+1` is the unobtainable lab)

**An existing rule that survived a fresh case is stronger than a new rule with
one.** Extend before you add.

---

## Reclaiming a slot

A slot is free when the previous lab is written up and its image removed. While
`docker ps` shows 4 lab containers and 4 writeups are in flight, Lane B is full.
The 4 containers left running by this session's workers are expected — restore
means *the lab is back to shipped*, not *the container is deleted*.

---

## Resume

All state is on disk. Nothing lives in a session.

```bash
cd /home/search14/dockerlabs-writeups
# 1. what is downloaded and verified
ls /home/search14/dockerlabs/state/*.ok | wc -l
# 2. what is solved and written up
ls corpus/ | grep -cE '^[0-9]+$'
# 3. what the queue still wants
env DL_ROOT=/home/search14/dockerlabs tooling/download-labs.sh status
# 4. restart the download lane over whatever is not yet .ok
env DL_ROOT=/home/search14/dockerlabs DL_PARALLEL=3 \
  tooling/download-labs.sh fetch $(comm -23 \
    <(cut -d'|' -f1 tooling/labs.manifest | sort) \
    <(ls /home/search14/dockerlabs/state/ | sed 's/\.ok$//' | sort) | tr '\n' ' ')
```

Step 4 is the whole restart. A lab already verified is skipped by the fetcher, so
re-running it over the full queue is safe and cheap.

---

## Convergence

Stop when a fetched batch yields no class the methodology lacks. Two signals:

1. **Every new lab is a harder instance of a class we have.** Difficulty is not
   coverage.
2. **A worker reports the class table already has the row.** That is the correct
   outcome, not a failure — it means the rule generalized.

A lab that resolves with **no new class and no new instrument defect** was still
worth running, but it is a signal to re-rank the queue, not to keep going.

**Id 268 is a permanent exception**, not a backlog item: the archive is truncated
by the server at 75–95% with no Range support, so it cannot be obtained. It stays
in the manifest as `pending` with that reason. Nothing about it is pending work.

---

## Next step

Fetch is running. Solve a lab whose `.ok` marker exists, using
[`RUNBOOK.md`](RUNBOOK.md), and check the class row in [`INDEX.md`](INDEX.md)
first — if the row names a heading, extend it instead of writing a new one.
