#!/usr/bin/env python3
r"""Build the static documentation site for the DockerLabs writeup corpus.

Reads the markdown corpus and writes a deterministic, self-contained site to
`_site/`. No network, no build step for the CSS or the JS, no framework.

Renderer: markdown-it-py (NOT Python-Markdown). The corpus relies on GFM's
escaped-pipe rule inside table cells (`\|`); Python-Markdown leaves the
backslash in the rendered output while markdown-it-py unescapes it to a
literal `|`.

Sources
    corpus/INDEX.md                  -> _site/labs.html
    corpus/HOW-IT-WAS-RESOLVED.md    -> _site/resolved.html
    method/self-corrections.md       -> _site/corrections.html
    method/retrieval-hazards.md      -> _site/hazards.html
    corpus/<id>/<NAME>-WRITEUP.md    -> _site/writeups/<id>-<slug>.html
    (other repo) sections/evidence.md-> _site/evidence.html
    hand-authored                    -> _site/index.html

The site is PUBLIC. Target-internal filesystem paths, container addresses and
cookie identifiers are redacted in the generated HTML only; the repository
markdown is never modified and is the authority.
"""

from __future__ import annotations

import html
import os
import re
import shutil
import sys
import unicodedata
from pathlib import Path

from markdown_it import MarkdownIt

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "_site"

EVIDENCE_SRC = Path("/home/search14/PenTestMethodology/sections/evidence.md")

MD = MarkdownIt("commonmark").enable("table").enable("strikethrough")

# --------------------------------------------------------------------------
# GitHub-compatible heading slugs, so in-page anchors in the corpus resolve.
# --------------------------------------------------------------------------


def slugify(text: str) -> str:
    text = re.sub(r"<[^>]+>", "", text)
    text = html.unescape(text)
    text = text.strip().lower()
    text = re.sub(r"[^\w\- ]", "", text, flags=re.UNICODE)
    return text.replace(" ", "-")


_SLUG_STATE: dict[str, dict[str, int]] = {}


def heading_ids(tokens, slugs: dict[str, int]) -> None:
    """Assign `id` attributes to headings, de-duplicating collisions."""
    for i, tok in enumerate(tokens):
        if tok.type != "heading_open":
            continue
        inline = tokens[i + 1]
        base = slugify(inline.content)
        n = slugs.get(base, 0)
        slugs[base] = n + 1
        tid = base if n == 0 else f"{base}-{n}"
        tok.attrSet("id", tid)


def render(md_text: str) -> str:
    env: dict[str, dict[str, int]] = {"slugs": {}}
    tokens = MD.parse(md_text)
    heading_ids(tokens, env["slugs"])
    return MD.renderer.render(tokens, MD.options, env)


# --------------------------------------------------------------------------
# Writeup inventory
# --------------------------------------------------------------------------

# Slugs are derived from the source path (`corpus/6/GRANDMA-WRITEUP.md` ->
# `6-grandma`) rather than from the display name in the index, so link
# rewriting is a pure function of the href that appears in the markdown.
SLUG_RE = re.compile(r"^(\d+)/(.+?)-WRITEUP\.md$")


def writeup_pages() -> dict[str, str]:
    """Map `corpus/<id>/<NAME>-WRITEUP.md` -> `writeups/<id>-<slug>.html`."""
    out: dict[str, str] = {}
    for path in sorted((REPO / "corpus").glob("*/*-WRITEUP.md")):
        rel = path.relative_to(REPO / "corpus").as_posix()
        m = SLUG_RE.match(rel)
        if not m:
            continue
        lab_id, name = m.group(1), m.group(2)
        out[rel] = f"writeups/{lab_id}-{name.lower()}.html"
    return out


# Lab display names, read out of corpus/INDEX.md, used for page titles and
# breadcrumbs only.
def lab_names() -> dict[str, str]:
    text = (REPO / "corpus" / "INDEX.md").read_text(encoding="utf-8")
    names: dict[str, str] = {}
    for m in re.finditer(r"^\|\s*(\d+)\s*\|\s*([^|]+?)\s*\|", text, re.M):
        names[m.group(1)] = m.group(2)
    return names


# --------------------------------------------------------------------------
# Link rewriting
# --------------------------------------------------------------------------

NAVLINKS = ["index.html", "evidence.html", "corrections.html",
            "hazards.html", "labs.html", "resolved.html"]

# Pages that are published, keyed by their repository-relative markdown path.
METHOD_PAGES = {
    "method/self-corrections.md": "corrections.html",
    "method/retrieval-hazards.md": "hazards.html",
}

EXTERNAL = re.compile(r"^(?:[a-z][a-z0-9+.\-]*:|//|#)", re.I)


def rewrite_href(href: str, prefix: str, writeups: dict[str, str]) -> str | None:
    """Map a markdown href onto a published page.

    Returns the new href, or None when the target is not published — in which
    case the caller drops the anchor and keeps the text, so the site contains
    no link that 404s.
    """
    if EXTERNAL.match(href):
        return href

    # Strip leading `../` and `./` and normalise to a repo-relative key.
    key = href
    while key.startswith("../"):
        key = key[3:]
    if key.startswith("./"):
        key = key[2:]

    if key in writeups:
        return prefix + writeups[key]
    if key.startswith("corpus/") and key[len("corpus/"):] in writeups:
        return prefix + writeups[key[len("corpus/"):]]
    if key in METHOD_PAGES:
        return prefix + METHOD_PAGES[key]
    if key in ("method/evidence.md", "sections/evidence.md"):
        return prefix + "evidence.html"
    if key in ("corpus/INDEX.md", "INDEX.md"):
        return prefix + "labs.html"
    if key == "corpus/HOW-IT-WAS-RESOLVED.md" or key == "HOW-IT-WAS-RESOLVED.md":
        return prefix + "resolved.html"
    return None


A_HREF = re.compile(r'<a href="([^"]*)"')


def rewrite_links(html_text: str, prefix: str, writeups: dict[str, str]) -> str:
    def sub(m: re.Match) -> str:
        new = rewrite_href(m.group(1), prefix, writeups)
        if new is None:
            # Unpublished target: neutralise the anchor, keep the words.
            return "<a-unlinked"
        return f'<a href="{new}"'

    return A_HREF.sub(sub, html_text)


# --------------------------------------------------------------------------
# Redaction — generated HTML only, never the source markdown
# --------------------------------------------------------------------------

REDACTION_NOTE = (
    "Target-internal paths, container addresses and cookie identifiers are "
    "redacted in this rendering."
)


def build_redactors(text: str) -> list[tuple[re.Pattern, str]]:
    """Collect the distinct literals to redact, then build the substitutions.

    The replacement preserves whatever discriminative detail the literal
    carried (the account name, the last octet, the header's role) and drops
    only the part that identifies the corpus host or the session.
    """
    rules: list[tuple[re.Pattern, str]] = []

    # Absolute and home-relative paths into the operator's own directories.
    # Only the directory *prefix* is dropped: the account name that follows is
    # load-bearing evidence in most of these engagements.
    rules.append((re.compile(r"/home/"), "[lab-home]/"))
    rules.append((re.compile(r"~/(?=[A-Za-z._])"), "[lab-home]/"))

    # The corpus checkout's own directory name, the operator's account, and
    # the agent runtime directory the harness was written to. The last one
    # names the tooling and the analysis host, so it goes too.
    rules.append((re.compile(r"\bdockerlabs-writeups\b"), "[corpus-repo]"))
    rules.append((re.compile(r"\bsearch14\b"), "[operator-account]"))
    rules.append((re.compile(r"opencode"), "[tool]"))

    # Docker bridge and RFC1918 addresses used as target hosts.
    def _net(m: re.Match) -> str:
        return "[net-" + m.group(1).replace(".", "-") + "]"

    def _lan(m: re.Match) -> str:
        return "[lan-" + m.group(1).replace(".", "-") + "]"

    rules.append((re.compile(r"172\.17\.([0-9]+(?:\.[0-9]+)*)"), _net))
    rules.append((re.compile(r"192\.168\.([0-9]+(?:\.[0-9]+)*)"), _lan))

    # Cookie identifiers. The value is the secret; the name only says which
    # mechanism was observed, so the name is replaced by its role.
    rules.append((re.compile(r"\bwordpress_logged_in[a-z0-9_]*", re.I),
                  "[wordpress-session-cookie]"))
    rules.append((re.compile(r"\bsqu_[a-z0-9_]*", re.I), "[waf-session-cookie]"))
    rules.append((re.compile(r"\bSet-Cookie\b", re.I), "[response-cookie-header]"))
    rules.append((re.compile(r"\bDL_COOKIE\b"), "[redacted-env-var]"))
    rules.append((re.compile(r"\bDL_PASS\b"), "[redacted-env-var]"))
    return rules


def redact(html_text: str) -> str:
    for pattern, repl in build_redactors(html_text):
        html_text = pattern.sub(repl, html_text)
    return html_text


# --------------------------------------------------------------------------
# Page shell
# --------------------------------------------------------------------------

def nav(prefix: str, current: str) -> str:
    labels = {
        "index.html": "Root cause",
        "evidence.html": "Evidence",
        "corrections.html": "Corrections",
        "hazards.html": "Hazards",
        "labs.html": "Labs",
        "resolved.html": "Resolutions",
    }
    items = []
    for href in NAVLINKS:
        cls = ' class="on"' if href == current else ""
        items.append(f'<a href="{prefix}{href}"{cls}>{labels[href]}</a>')
    return ('<header><a class="brand" href="%sindex.html">DockerLabs corpus</a>'
            '<nav>%s</nav></header>' % (prefix, "".join(items)))


def footer(prefix: str) -> str:
    return (
        "<footer>"
        "<p><strong>The markdown in the repository is the authority.</strong> "
        "This site is a rendering of it. Where the two disagree, the "
        "repository is correct and this page is wrong &mdash; report it as a "
        "build defect, not as a finding.</p>"
        f"<p>{REDACTION_NOTE} The repository markdown is unredacted.</p>"
        "<p>Counts on this site are read out of the source files at build "
        "time, and the renderer is <code>markdown-it-py</code>. Nothing on "
        "this page was written by hand except this footer, the homepage and "
        "the stylesheet.</p>"
        "</footer>"
    )


def page(title: str, prefix: str, current: str, body: str,
         extra_head: str = "", extra_body: str = "") -> str:
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<meta name="robots" content="noindex">\n'
        f"<title>{html.escape(title)} &middot; DockerLabs corpus</title>\n"
        f'<link rel="stylesheet" href="{prefix}assets/site.css">\n'
        f"{extra_head}"
        "</head>\n<body>\n"
        f"{nav(prefix, current)}\n"
        f'<main>\n{body}\n</main>\n'
        f"{footer(prefix)}\n"
        f"{extra_body}"
        "</body>\n</html>\n"
    )


CSS = """/* DockerLabs corpus — no build step, no external font, no CDN. */
:root {
  color-scheme: light dark;
  --bg: #ffffff;
  --fg: #14171a;
  --muted: #5b6570;
  --line: #d8dee4;
  --surface: #f6f8fa;
  --accent: #0b5cad;
  --warn-bg: #fff5e6;
  --warn-line: #d08700;
  --warn-fg: #6b4300;
  --tile: #f6f8fa;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f1216;
    --fg: #e6e9ec;
    --muted: #9aa5b1;
    --line: #2a313a;
    --surface: #171b21;
    --accent: #79b8ff;
    --warn-bg: #2a2113;
    --warn-line: #d08700;
    --warn-fg: #f0c674;
    --tile: #171b21;
  }
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--fg);
  font-family: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue",
    Arial, "Noto Sans", sans-serif;
  font-size: 16px;
  line-height: 1.6;
}
header {
  position: sticky;
  top: 0;
  z-index: 10;
  display: flex;
  flex-wrap: wrap;
  gap: .25rem 1rem;
  align-items: baseline;
  padding: .6rem 1rem;
  background: var(--bg);
  border-bottom: 1px solid var(--line);
}
header .brand { font-weight: 700; text-decoration: none; color: var(--fg); }
header nav { display: flex; flex-wrap: wrap; gap: .25rem .9rem; }
header nav a {
  color: var(--muted);
  text-decoration: none;
  font-size: .92rem;
  padding: .1rem 0;
  border-bottom: 2px solid transparent;
}
header nav a:hover, header nav a:focus { color: var(--accent); }
header nav a.on { color: var(--fg); border-bottom-color: var(--accent); }
main {
  max-width: 62rem;
  margin: 0 auto;
  padding: 1.5rem 1rem 4rem;
}
h1 { font-size: 1.9rem; line-height: 1.25; margin: .2rem 0 1rem; }
h2 { font-size: 1.35rem; margin: 2.2rem 0 .6rem; padding-bottom: .2rem;
     border-bottom: 1px solid var(--line); }
h3 { font-size: 1.1rem; margin: 1.6rem 0 .4rem; }
h4 { font-size: 1rem; margin: 1.2rem 0 .3rem; color: var(--muted); }
p, ul, ol { margin: .6rem 0; }
a { color: var(--accent); }
hr { border: 0; border-top: 1px solid var(--line); margin: 2rem 0; }
code, kbd, samp, pre {
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas,
    "DejaVu Sans Mono", monospace;
  font-size: .9em;
}
code { background: var(--surface); border: 1px solid var(--line);
       border-radius: 4px; padding: .05em .3em; }
pre { background: var(--surface); border: 1px solid var(--line);
      border-radius: 6px; padding: .8rem; overflow-x: auto; line-height: 1.45; }
pre code { background: none; border: 0; padding: 0; }
blockquote {
  margin: 1rem 0;
  padding: .6rem .9rem;
  border-left: 4px solid var(--line);
  background: var(--surface);
  color: var(--fg);
}
blockquote p:first-child { margin-top: 0; }
blockquote p:last-child { margin-bottom: 0; }
/* Warning variant of the same block. */
.callout {
  border-left: 4px solid var(--warn-line);
  background: var(--warn-bg);
  color: var(--warn-fg);
}
.callout strong { color: inherit; }
/* Tables scroll instead of overflowing on a phone. */
table {
  display: block;
  width: 100%;
  max-width: 100%;
  overflow-x: auto;
  border-collapse: collapse;
  margin: 1rem 0;
  font-size: .92rem;
  -webkit-overflow-scrolling: touch;
}
th, td { border: 1px solid var(--line); padding: .4rem .55rem;
         text-align: left; vertical-align: top; }
th { background: var(--surface); position: sticky; top: 0; }
tbody tr:nth-child(even) { background: color-mix(in srgb, var(--tile) 55%, transparent); }
a-unlinked { color: inherit; text-decoration: none; }
a-unlinked::after { content: " \\203A"; color: var(--muted); }
.tiles { display: flex; flex-wrap: wrap; gap: .8rem; margin: 1.2rem 0; }
.tile {
  flex: 1 1 12rem;
  background: var(--tile);
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: .8rem .9rem;
}
.tile .n { display: block; font-size: 1.9rem; font-weight: 700;
           line-height: 1.1; }
.tile .l { display: block; color: var(--muted); font-size: .86rem; }
.tile.emph { border-color: var(--accent); border-width: 2px; }
.tile.emph .n { color: var(--accent); }
.filter { display: flex; flex-wrap: wrap; gap: .6rem; align-items: center;
          margin: 1rem 0; }
.filter input {
  flex: 1 1 16rem;
  font: inherit;
  padding: .45rem .6rem;
  color: var(--fg);
  background: var(--bg);
  border: 1px solid var(--line);
  border-radius: 6px;
}
.filter .count { color: var(--muted); font-size: .9rem; font-variant-numeric: tabular-nums; }
.crumb { color: var(--muted); font-size: .88rem; margin: 0 0 .2rem; }
footer {
  max-width: 62rem;
  margin: 0 auto;
  padding: 1.2rem 1rem 3rem;
  border-top: 1px solid var(--line);
  color: var(--muted);
  font-size: .86rem;
}
footer p { margin: .4rem 0; }
@media print {
  header { position: static; }
  th { position: static; }
}
"""

FILTER_JS = """<script>
(function () {
  var input = document.getElementById("lab-filter");
  var count = document.getElementById("lab-count");
  var rows = Array.prototype.slice.call(
    document.querySelectorAll("#lab-table tbody tr"));
  var total = rows.length;
  function apply() {
    var q = input.value.trim().toLowerCase();
    var shown = 0;
    rows.forEach(function (row) {
      var hit = q === "" || row.textContent.toLowerCase().indexOf(q) !== -1;
      row.hidden = !hit;
      if (hit) { shown++; }
    });
    count.textContent = shown === total
      ? total + " of " + total + " rows"
      : shown + " of " + total + " rows match";
  }
  input.addEventListener("input", apply);
  apply();
})();
</script>
"""


def strip_frontmatter(text: str) -> str:
    if not text.startswith("---"):
        return text
    m = re.match(r"^---\r?\n.*?\r?\n---\r?\n", text, re.S)
    return text[m.end():] if m else text


# --------------------------------------------------------------------------
# index.html — hand-authored
# --------------------------------------------------------------------------

INDEX_BODY = """<h1>A tool that found nothing and a tool that never looked
produce identical output.</h1>

<p>Across {ENGAGEMENTS} resolved engagements the dominant failure was never a
missing technique. It was a measurement that was wrong, producing output that
was indistinguishable from a result. Every case below shipped well-formed
output. Not one of them errored.</p>

<div class="tiles">
  <div class="tile"><span class="n">{ENGAGEMENTS}</span><span class="l">engagements
  resolved</span></div>
  <div class="tile"><span class="n">{CORRECTIONS}</span><span class="l">instrument
  defects catalogued</span></div>
  <div class="tile"><span class="n">{HAZARDS}</span><span class="l">retrieval
  hazards catalogued</span></div>
  <div class="tile emph"><span class="n">0</span><span class="l">looked like an
  error</span></div>
</div>

<h2 id="why-it-matters">Why this matters more than a missing technique</h2>

<p>A missing technique is <strong>visible</strong>. The run stops, the report
says <em>not attempted</em>, and the gap is in the coverage list where somebody
will read it. A broken measurement is <strong>invisible</strong>. It produces a
complete, well-formed, plausible answer, and the answer is wrong in the
direction that makes the engagement look finished.</p>

<p>Of the nine instruments the corpus tallies, six would have
<strong>deleted a finding that existed</strong> and three would have
<strong>invented one</strong>. A negative result is the only output nobody
cross-checks &mdash; which is exactly why the defect has to be ruled out from
outside the output.</p>

<h2 id="three-questions">The three questions every negative must answer</h2>

<table>
<thead><tr><th>#</th><th>Question</th><th>If unanswered</th>
<th>Discriminator</th></tr></thead>
<tbody>
<tr><td>1</td><td>Did the tool work?</td>
<td>An oracle that cannot fire reports absence</td>
<td>Force a positive through it, <strong>before</strong> believing any
negative</td></tr>
<tr><td>2</td><td>Did it look where it needed to?</td>
<td>A blind spot reads as an absent service</td>
<td>A work count: rows, bytes, candidates, addresses</td></tr>
<tr><td>3</td><td>Is the failure the target&rsquo;s and not mine?</td>
<td>Real findings get deleted and filed as clean</td>
<td>Change one variable, or probe a known-good reference</td></tr>
</tbody>
</table>

<blockquote class="callout">
<p><strong>They are ordered, not interchangeable.</strong> A green positive
control with a zero work count still fails &mdash; the control may have fired
on a code path the target never takes.</p>
</blockquote>

<h2 id="quick-path">Quick path</h2>

<ol>
<li><strong>Read <a href="corrections.html">the {CORRECTIONS} corrections</a>.</strong>
The failures that recur, cheapest first. Every entry names the lab that
produced it.</li>
<li><strong>Check your instrument against
<a href="hazards.html">the {HAZARDS} retrieval hazards</strong>.</strong> These
are <em>correct</em> instruments pointed at the wrong question &mdash; the class
that still returns a clean negative.</li>
<li><strong>Run the three questions above before writing any negative.</strong>
All three, in order, with the discriminator attached.</li>
<li><strong>Then look up the lab.</strong> The
<a href="labs.html">index</a> carries the class and the discriminator that
settled it; <a href="resolved.html">the resolution map</a> says which single
measurement closed each one.</li>
</ol>

<h2 id="next-step">Next step</h2>

<p>If you are about to write the words <em>not present</em>, <em>no
results</em>, or <em>not exploitable</em>, stop and read
<a href="evidence.html">the evidence discipline</a> first. That page is the
long form of the sentence at the top of this one.</p>
"""


def build_index(counts: dict[str, int]) -> str:
    body = INDEX_BODY.format(**counts)
    return page("A tool that found nothing and a tool that never looked",
                "", "index.html", body)


# --------------------------------------------------------------------------
# Build
# --------------------------------------------------------------------------

def read_source(rel: str) -> str:
    path = REPO / rel
    if not path.exists():
        raise SystemExit(f"FATAL: required source missing: {path}")
    return path.read_text(encoding="utf-8")


def evidence_body() -> str:
    if not EVIDENCE_SRC.exists():
        return (
            "<h1>Evidence</h1>\n"
            '<blockquote class="callout"><p><strong>Source unavailable.</strong> '
            "This page is rendered from <code>sections/evidence.md</code> in the "
            "PenTestMethodology repository, which was not present on this machine "
            "at build time. Nothing has been substituted for it.</p></blockquote>\n"
            '<p>Read <a href="index.html">the root cause</a> and '
            '<a href="corrections.html">the corrections</a> in the meantime.</p>\n'
        )
    text = strip_frontmatter(EVIDENCE_SRC.read_text(encoding="utf-8"))
    return rewrite_links(render(text), "", writeup_pages())


def build() -> None:
    counts = {
        "ENGAGEMENTS": len(writeup_pages()),
        "CORRECTIONS": len(re.findall(
            r"^## \d+\.", read_source("method/self-corrections.md"), re.M)),
        "HAZARDS": len(re.findall(
            r"^\| \*\*", read_source("method/retrieval-hazards.md"), re.M)),
    }

    if OUT.exists():
        shutil.rmtree(OUT)
    (OUT / "writeups").mkdir(parents=True)
    (OUT / "assets").mkdir(parents=True)

    (OUT / "assets" / "site.css").write_text(CSS, encoding="utf-8")

    writeups = writeup_pages()
    names = lab_names()

    written: list[str] = []

    def emit(out_rel: str, html_text: str) -> None:
        (OUT / out_rel).write_text(html_text, encoding="utf-8")
        written.append(out_rel)

    # Root-level pages: one directory deep, so links carry no prefix.
    emit("index.html", build_index(counts))
    emit("evidence.html", page("Evidence", "", "evidence.html", evidence_body()))
    for rel, out_rel, title, current in (
        ("method/self-corrections.md", "corrections.html",
         "Self-corrections", "corrections.html"),
        ("method/retrieval-hazards.md", "hazards.html",
         "Retrieval hazards", "hazards.html"),
        ("corpus/HOW-IT-WAS-RESOLVED.md", "resolved.html",
         "How each lab was resolved", "resolved.html"),
    ):
        body = render(strip_frontmatter(read_source(rel)))
        body = rewrite_links(body, "", writeups)
        emit(out_rel, page(title, "", current, body))

    # The labs index gets a client-side filter above its table.
    body = render(strip_frontmatter(read_source("corpus/INDEX.md")))
    body = rewrite_links(body, "", writeups)
    body = body.replace("<table>", '<div class="filter">'
                        '<label for="lab-filter">Filter rows</label>'
                        '<input type="search" id="lab-filter" '
                        'placeholder="lab number, name, class, reward" '
                        'autocomplete="off">'
                        '<span class="count" id="lab-count"></span>'
                        "</div>\n"
                        '<table id="lab-table">', 1)
    emit("labs.html", page("Labs", "", "labs.html", body,
                           extra_body=FILTER_JS))

    # Writeups: one directory deeper, so their links need the `../` prefix.
    for rel, out_rel in sorted(writeups.items(), key=lambda kv: kv[1]):
        lab_id = rel.split("/")[0]
        src = read_source(f"corpus/{rel}")
        body = render(strip_frontmatter(src))
        body = rewrite_links(body, "../", writeups)
        crumb = (f'<p class="crumb"><a href="../labs.html">Labs</a> &rsaquo; '
                 f'{html.escape(names.get(lab_id, lab_id))}</p>')
        title = f"Lab {lab_id} {names.get(lab_id, '')}".strip()
        emit(out_rel, page(title, "../", "", crumb + body))

    # Redaction runs last, over the finished HTML, so it cannot be bypassed by
    # markdown that reaches the output through an unexpected path.
    for rel in written:
        p = OUT / rel
        p.write_text(redact(p.read_text(encoding="utf-8")), encoding="utf-8")

    print(f"build ok: {len(written)} pages -> {OUT.relative_to(REPO)}/")
    print(f"  engagements={counts['ENGAGEMENTS']} "
          f"corrections={counts['CORRECTIONS']} hazards={counts['HAZARDS']}")


if __name__ == "__main__":
    sys.exit(build())
