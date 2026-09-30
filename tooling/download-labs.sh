#!/usr/bin/env bash
# DockerLabs lab fetcher — standalone, no agent required.
#
# Why this exists: the platform does NOT support HTTP Range, so a partial
# download cannot be resumed. Every attempt must complete in one shot, and a
# timeout means starting the whole file again. That constraint drives
# everything here: long timeouts, retry-from-scratch, and a verify step that
# does not trust the exit code.
#
# Usage:
#   ./download-labs.sh list                      # dump catalog (id|slug|difficulty|label)
#   ./download-labs.sh fetch 148 295 62         # fetch by platform id
#   ./download-labs.sh fetch --manifest labs.manifest
#   ./download-labs.sh fetch --all              # everything in the manifest
#   ./download-labs.sh status                   # what is done, what is pending
#   ./download-labs.sh extract 148              # unpack a verified archive
#
# Config via environment:
#   DL_USER / DL_PASS   platform credentials (needed to resolve URLs)
#   DL_COOKIE           pre-existing session cookie, skips login
#   DL_ROOT             destination root (default: script dir)
#   DL_TIMEOUT          per-attempt seconds (default 3600)
#   DL_RETRIES          attempts per file, from scratch (default 4)

set -uo pipefail

# Working root. Deliberately NOT the script's own directory: this tool ships
# inside an evidence repo, and dist/, state/ and logs/ must never be created
# inside it. state/ holds a live session cookie, which must stay out of git.
DL_ROOT="${DL_ROOT:-${XDG_DATA_HOME:-$HOME/.local/share}/dockerlabs}"
PLATFORM="https://dockerlabs.es"
CDN_RE='https://gestion-maquinas\.dockerlabs\.es/dl/[A-Za-z0-9._-]+\.(zip|tar)'
TIMEOUT="${DL_TIMEOUT:-3600}"
RETRIES="${DL_RETRIES:-4}"
DIST="$DL_ROOT/dist"
STATE="$DL_ROOT/state"
LOGS="$DL_ROOT/logs"
JAR="$STATE/session.cookie"

mkdir -p "$DIST" "$STATE" "$LOGS"

log()  { printf '%s [%s] %s\n' "$(date -u +%H:%M:%S)" "$1" "${*:2}"; }
die()  { log ERR "$*"; exit 1; }

# ---------------------------------------------------------------- credentials

login() {
  [[ -n "${DL_COOKIE:-}" ]] && { log INFO "using DL_COOKIE from environment"; return 0; }
  [[ -s "$JAR" ]] && { log INFO "reusing existing session"; return 0; }
  [[ -n "${DL_USER:-}" && -n "${DL_PASS:-}" ]] || die "set DL_USER and DL_PASS, or pass DL_COOKIE"

  local page token
  page="$(curl -sS -c "$JAR" --max-time 30 -A "$UA" "$PLATFORM/login")" || die "login page unreachable"
  token="$(grep -oE '<meta name="csrf-token" content="[a-f0-9]{64}"' <<<"$page" | grep -oE '[a-f0-9]{64}' | head -1)"
  [[ -n "$token" ]] || die "could not read CSRF token from login page"

  # Build the body with a JSON encoder so $ # and other shell-hostile
  # characters in a password cannot corrupt the request.
  local body
  body="$(printf '{"username":%s,"password":%s}' \
          "$(printf '%s' "$DL_USER"  | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))')" \
          "$(printf '%s' "$DL_PASS"  | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))')")"

  local resp
  resp="$(curl -sS -b "$JAR" -c "$JAR" --max-time 30 -A "$UA" \
          -H "Content-Type: application/json" -H "X-CSRF-Token: $token" \
          -H "Referer: $PLATFORM/login" --data-binary "$body" \
          "$PLATFORM/api/auth/login")" || die "login request failed"

  grep -q '"success":true' <<<"$resp" || die "login rejected: $resp"
  log INFO "authenticated as $DL_USER"
}

# ------------------------------------------------------------------ catalog

catalog() {
  local page
  page="$(curl -sS -L --max-time 45 -A "$UA" "$PLATFORM/")" || die "platform unreachable"
  echo "$page" > "$STATE/catalog.html"
  python3 - "$STATE/catalog.html" <<'PY'
import re,sys
s=open(sys.argv[1],encoding='utf-8',errors='replace').read()
rows={}
for m in re.finditer(r'<div onclick="presentacion\((.*?)\)"\s*class="maquina-item (\S*)[^>]*data-id="(\d+)"',s,re.S):
    v=re.findall(r'&#34;(.*?)&#34;',m.group(1))
    if len(v)>=6: rows[m.group(3)]=(v[0],m.group(2))
inv={v[0]:k for k,v in rows.items()}
seen=set()
for m in re.finditer(r'onclick="descripcion\(&#34;(.*?)&#34;, &#34;(.*?)&#34;\)',s,re.S):
    name,d=m.group(1),m.group(2)
    i=inv.get(name)
    if i and i not in seen:
        seen.add(i); print(f"{i}|{rows[i][0]}|{rows[i][1]}|{d}")
PY
}

# ------------------------------------------------------------------ resolve

resolve_url() {
  local id="$1" page url
  page="$(curl -sS -b "$JAR" -L --max-time 45 -A "$UA" "$PLATFORM/maquinas/$id/descargar")" || return 1
  # The filename casing is not predictable: spain ships as .tar, others .zip,
  # and Baremetal is capitalised. Match case-insensitively and take the path.
  url="$(grep -oE "$CDN_RE" <<<"$page" | head -1)"
  [[ -n "$url" ]] || return 1
  printf '%s' "$url"
}

filename_of() { basename "$1"; }

# ----------------------------------------------------------------- download

fetch_one() {
  local id="$1" url fname dest attempt size

  if resolve_url "$id" > "$STATE/$id.url" 2>/dev/null && [[ -s "$STATE/$id.url" ]]; then
    url="$(cat "$STATE/$id.url")"
  else
    log WARN "id $id: no download link (locked, or the page changed) — skipping"
    return 2
  fi
  fname="$(filename_of "$url")"
  dest="$DIST/$fname"

  if [[ -f "$STATE/$id.ok" && -f "$dest" ]]; then
    log INFO "id $id: already verified ($fname) — skip"
    return 0
  fi

  if [[ -f "$dest" ]]; then
    if verify "$dest"; then
      log INFO "id $id: existing $fname verifies — marking done"
      : > "$STATE/$id.ok"; return 0
    fi
    log WARN "id $id: $fname present but does not verify — discarding"
    rm -f "$dest"
  fi

  local expected=0 trunc_streak=0
  for (( attempt=1; attempt<=RETRIES; attempt++ )); do
    log INFO "id $id: attempt $attempt/$RETRIES — $fname"
    rm -f "$dest.part"
    # No -C -. The server ignores Range, so resume is impossible by design.
    if curl -sS --fail -o "$dest.part" -D "$STATE/$id.hdr" --max-time "$TIMEOUT" \
            -A "$UA" --speed-limit 2048 --speed-time 120 "$url"; then
      size=$(stat -c%s "$dest.part" 2>/dev/null || echo 0)
      # The platform serves HEAD as 405, so the length comes from the GET headers.
      if (( expected == 0 )); then
        expected=$(tr -d '\r' < "$STATE/$id.hdr" \
                   | grep -i '^content-length:' | tail -1 | awk '{print $2}')
        [[ "$expected" =~ ^[0-9]+$ ]] || expected=0
      fi
      if mv "$dest.part" "$dest" && verify "$dest"; then
        : > "$STATE/$id.ok"
        log OK "id $id: $fname verified ($size bytes)"
        return 0
      fi
      # curl exited 0 yet the archive is unusable. Two different faults live here
      # and conflating them wastes a real lab. Measured on id 268, four identical
      # failures at 75-95% of 116,916,224 bytes: the server closed a long
      # response near its end. With no Range support every retry discards ~100 MB
      # of good transfer, so a systematic cut is abandoned early.
      #
      # But id 254 arrived at 107,479,040 of 107,479,040 — *complete* — and an
      # earlier version of this test read `>= 80%` and declared it truncated. A
      # full-length archive that fails verification is corrupt, not cut, and the
      # two need opposite responses: a cut is hopeless, corruption may be worth
      # one more fetch in case the bytes were mangled in transit.
      if (( expected > 0 && size < expected && size * 100 >= expected * 80 )); then
        trunc_streak=$(( trunc_streak + 1 ))
        log WARN "id $id: $fname truncated by server — got $size of $expected bytes (${trunc_streak}x)"
        rm -f "$dest"
        if (( trunc_streak >= 2 )); then
          log ERR "id $id: giving up — server truncates this archive ($size/$expected) and Range is unsupported, so it cannot be resumed"
          return 3
        fi
        sleep 5
        continue
      fi
      if (( expected > 0 && size >= expected )); then
        log ERR "id $id: $fname is COMPLETE at $size/$expected bytes but fails verification — this is corruption, not truncation. Refusing to retry; a cut and a corrupt archive are different faults and a retry that cannot resume fixes neither"
        rm -f "$dest"
        return 4
      fi
      log WARN "id $id: $fname downloaded but failed verification — retrying from scratch"
      rm -f "$dest"
    else
      log WARN "id $id: transfer interrupted — retrying from scratch (no resume possible)"
    fi
    rm -f "$dest.part"
    sleep 5
  done

  log ERR "id $id: giving up on $fname after $RETRIES attempts"
  return 1
}

# -------------------------------------------------------------------- verify

# An exit code of zero from curl only means bytes arrived. This asks whether the
# bytes are a readable archive — the only thing that actually matters here,
# because a truncated transfer still exits 0 on some proxies.
verify() {
  local f="$1"
  case "$f" in
    *.zip) unzip -tqq "$f" >/dev/null 2>&1 ;;
    *.tar) tar -tf "$f" >/dev/null 2>&1 ;;
    *)     [[ -s "$f" ]] ;;
  esac
}

# ------------------------------------------------------------------- extract

extract_one() {
  local id="$1" fname dest
  fname="$(cat "$STATE/$id.url" 2>/dev/null | xargs -r basename)"
  [[ -n "$fname" && -f "$DIST/$fname" ]] || die "id $id: no verified archive; run fetch first"
  dest="$DL_ROOT/labs/$id"
  mkdir -p "$dest"
  case "$fname" in
    *.zip) unzip -oq "$DIST/$fname" -d "$dest" ;;
    *.tar) tar -xf  "$DIST/$fname" -C "$dest" ;;
  esac
  log OK "id $id: extracted to $dest"
}

# -------------------------------------------------------------------- status

status() {
  printf '%-6s %-9s %-12s %s\n' ID STATE FILE LABEL
  while IFS='|' read -r id slug diff label; do
    [[ -n "$id" ]] || continue
    [[ "$id" == \#* ]] && continue
    local st="pending" fname=""
    [[ -f "$STATE/$id.ok" ]] && st="OK"
    [[ -f "$STATE/$id.url" ]] && fname="$(basename "$(cat "$STATE/$id.url")")"
    printf '%-6s %-9s %-12s %s\n' "$id" "$st" "${fname:--}" "${label:0:44}"
  done < "${1:-$DL_ROOT/labs.manifest}"
}

# ---------------------------------------------------------------------- main

UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
MANIFEST="$DL_ROOT/labs.manifest"
CMD="${1:-status}"; shift || true

case "$CMD" in
  list) catalog ;;
  fetch)
    login
    ids=()
    case "${1:-}" in
      --all)      while IFS='|' read -r i _; do [[ -n "$i" && "$i" != \#* ]] && ids+=("$i"); done < "$MANIFEST" ;;
      --manifest) while IFS='|' read -r i _; do [[ -n "$i" && "$i" != \#* ]] && ids+=("$i"); done < "$2" ;;
      *)         ids=("$@") ;;
    esac
    [[ ${#ids[@]} -gt 0 ]] || die "nothing to fetch"
    # Parallel, capped. The reason is fault isolation, NOT bandwidth: there is
    # no HTTP Range on this CDN, so one unresumable archive (id 268 died on four
    # consecutive attempts, ~20 minutes) would otherwise stall the whole queue.
    # Each lab is independent; a slow one must not hold the others.
    parallel="${DL_PARALLEL:-3}"
    (( parallel < 1 )) && parallel=1
    log INFO "fetching ${#ids[@]} lab(s), $parallel at a time"
    fail=0; running=0
    for i in "${ids[@]}"; do
      while (( $(jobs -rp | wc -l) >= parallel )); do wait -n 2>/dev/null || sleep 2; done
      ( fetch_one "$i" || echo "$i" >> "$STATE/.failed" ) &
      running=$(( running + 1 ))
    done
    wait
    unresolved=0
    [[ -f "$STATE/.failed" ]] && unresolved=$(sort -u "$STATE/.failed" | wc -l)
    rm -f "$STATE/.failed"
    log INFO "batch finished — ${#ids[@]} requested, $unresolved unresolved"
    status
    exit $(( unresolved > 0 ? 1 : 0 ))
    ;;
  extract) login; for i in "$@"; do extract_one "$i" || fail=1; done; exit "${fail:-0}" ;;
  status)  status "$MANIFEST" ;;
  *) sed -n '2,14p' "$0"; exit 1 ;;
esac
