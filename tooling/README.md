# DockerLabs pipeline

Two separate jobs, deliberately not combined:

1. **Fetch** — `download-labs.sh`, runs on its own, no agent involved.
2. **Solve** — the agent's job, starts only after an archive is verified.

Keeping them apart is the point. Downloads are slow (4–8 min for 200–800 MB) and
unreliable (no resume). Solving needs judgment and a clean context. Coupling them
means every network hiccup stalls a pentest and every solve retries a download.

## Layout

```
download-labs.sh     the fetcher
labs.manifest        work queue: id | label | difficulty | why it is queued
dist/                verified archives
state/               one .ok marker per verified id, plus session.cookie
labs/<id>/           extracted images and sources
logs/                fetch logs
```

## Why the fetcher looks the way it does

**No resume, by design of the platform.** The CDN does not honour HTTP Range, so a
partial transfer is unrecoverable — `curl -C -` fails with *"does not seem to support
byte ranges"*. Every attempt therefore restarts from zero. The script deletes
`.part` and retries whole, with a 3600 s ceiling and a low-speed abort
(`--speed-limit 2048 --speed-time 120`) so a stalled transfer is caught in two
minutes instead of hanging for the full hour.

**Exit code zero is not evidence.** curl returning success only means bytes
arrived. Every download is then passed to `unzip -tqq` or `tar -tf`, and only a
readable archive earns a `.ok` marker. A truncated file is a normal outcome here and
`status` would otherwise report progress that does not exist.

**Filenames are not predictable.** The platform serves `.zip` for most labs, `.tar`
for others, and the casing is inconsistent — `Baremetal.zip` is capitalised,
`pingupenguin.zip` is not. The CDN URL is read out of the machine's own download
page rather than guessed from the label.

**Credentials go through a JSON encoder.** A password containing `$` or `#` written
into a request body by hand will silently corrupt the body. The script builds the
JSON with `json.dumps` so shell metacharacters survive.

**Some archives cannot be fetched at all.** Measured on id 268 (`kmspwned.zip`,
116,916,224 bytes): four consecutive attempts each transferred between 75% and 95%
of the file and then died, with `curl` exiting **0** every time — the server closes
a long response without signalling an error, so curl believes it finished. `Range`
is answered with `200`, not `206`, so there is no way to fetch the tail. The
combination makes the file permanently unobtainable through this endpoint, and the
wasted cost is real: with no resume, every attempt throws away ~100 MB of good
transfer.

The script now distinguishes this from ordinary flakiness. It reads the expected
length from the GET headers (the platform answers `HEAD` with `405`), and if a
download dies at ≥80% of it **twice in a row** it stops and says so, instead of
burning every retry on a failure it cannot fix. A transfer that dies early is still
retried normally — a short download is not truncation, and conflating the two would
hide real instability.

## Usage

```bash
export DL_USER='...' DL_PASS='...'

./download-labs.sh list                  # dump the whole catalog
./download-labs.sh status                # what is verified, what is pending
./download-labs.sh fetch 255 186         # by platform id
./download-labs.sh fetch --all           # everything in the manifest
./download-labs.sh extract 255           # unpack a verified archive
```

Run it detached for long batches:

```bash
setsid bash -c './download-labs.sh fetch --all >> logs/fetch.log 2>&1' < /dev/null &
```

Session state is cached in `state/session.cookie`, so only the first fetch of a
day needs credentials. `DL_COOKIE` bypasses login entirely if you bring your own.

## Adding a lab

Append one line to `labs.manifest`. The fourth field is the reason, and it should be
the *reason it is worth the hours*: a class the methodology lacks, not a class that
is merely available. The first five solved labs were picked that way, and three of
the twelve queued were rejected because they would have duplicated an oracle that
already exists.

## After a lab is solved

1. Write the writeup under `labs/<id>/` — English, findings with CWE, literal
   evidence, and an **autocorrection section** when the first approach was wrong.
   That section has been the most valuable part every time.
2. Record the transferable rules in Engram, project `pentestmethodology`.
3. Check the oracles already in `sections/api_web.md`, `sections/infrastructure.md`
   and `sections/decision-making.md` **before** adding anything. Density beats
   coverage; four of the last five labs' classes were already covered and were
   correctly not duplicated.
4. Restore the lab to its shipped state, including any artefacts you created.
